//! Typed claims of the tokens Lock issues.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

fn audience<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    Ok(match Option::<Audience>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(Audience::One(one)) => vec![one],
        Some(Audience::Many(many)) => many,
    })
}

/// Lock formats `iat`, `exp` and `nbf` with microsecond precision (a float such as
/// `1762085339.123456`) unless the microseconds happen to be zero, so a timestamp is an integer or
/// a float. Floats truncate to whole seconds, as the validators already read them.
#[derive(Deserialize)]
#[serde(untagged)]
enum Timestamp {
    Whole(i64),
    Fractional(f64),
}

impl Timestamp {
    fn seconds(self) -> i64 {
        match self {
            Timestamp::Whole(whole) => whole,
            // `as i64` saturates, which is the intended clamp for absurd values.
            Timestamp::Fractional(fractional) => fractional as i64,
        }
    }
}

fn timestamp<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    Ok(Timestamp::deserialize(deserializer)?.seconds())
}

fn optional_timestamp<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    Ok(Option::<Timestamp>::deserialize(deserializer)?.map(Timestamp::seconds))
}

/// The validated claims of an ID token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// The issuer, the realm URL.
    pub iss: String,
    /// The stable subject identifier of the user in this realm.
    pub sub: String,
    /// The audience; always includes the client id.
    #[serde(deserialize_with = "audience", default)]
    pub aud: Vec<String>,
    /// Expiry, seconds since the Unix epoch.
    #[serde(deserialize_with = "timestamp")]
    pub exp: i64,
    /// Issue time, seconds since the Unix epoch.
    #[serde(deserialize_with = "timestamp")]
    pub iat: i64,
    /// The nonce of the authorization request.
    #[serde(default)]
    pub nonce: Option<String>,
    /// The authorized party.
    #[serde(default)]
    pub azp: Option<String>,
    /// The provider session id, which a back-channel logout token names again.
    #[serde(default)]
    pub sid: Option<String>,
    /// When the user authenticated.
    #[serde(default, deserialize_with = "optional_timestamp")]
    pub auth_time: Option<i64>,
    /// The display name (`profile` scope).
    #[serde(default)]
    pub name: Option<String>,
    /// The given name (`profile` scope).
    #[serde(default)]
    pub given_name: Option<String>,
    /// The family name (`profile` scope).
    #[serde(default)]
    pub family_name: Option<String>,
    /// Lock lists no `preferred_username` in its `claims_supported`; present only if configured.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// The email address (`email` scope).
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the email address is verified.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Every other claim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The validated claims of a JWT access token (`typ: at+jwt`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// The issuer.
    pub iss: String,
    /// The user id, or the client id for a client credentials token.
    pub sub: String,
    /// The audiences of the token.
    #[serde(deserialize_with = "audience", default)]
    pub aud: Vec<String>,
    /// Expiry, seconds since the Unix epoch.
    #[serde(deserialize_with = "timestamp")]
    pub exp: i64,
    /// Issue time.
    #[serde(default, deserialize_with = "optional_timestamp")]
    pub iat: Option<i64>,
    /// Not before.
    #[serde(default, deserialize_with = "optional_timestamp")]
    pub nbf: Option<i64>,
    /// The token id.
    #[serde(default)]
    pub jti: Option<String>,
    /// The client the token was issued to.
    #[serde(default)]
    pub client_id: Option<String>,
    /// The granted scopes, space-delimited.
    #[serde(default)]
    pub scope: Option<String>,
    /// The granted scopes as a list.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Every other claim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl AccessTokenClaims {
    /// Whether the token carries `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| granted == scope)
            || self
                .scope
                .as_deref()
                .is_some_and(|all| all.split(' ').any(|granted| granted == scope))
    }
}

/// A validated back-channel logout token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutToken {
    /// The provider session to end.
    pub sid: String,
    /// The user, empty when the token names none.
    pub sub: String,
    /// The token id, used for replay protection.
    pub jti: Option<String>,
    /// Expiry, seconds since the Unix epoch.
    #[serde(deserialize_with = "timestamp")]
    pub exp: i64,
}

/// The `/oauth/userinfo` response. Only `sub` is unconditional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    /// The stable subject identifier.
    pub sub: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Given name.
    #[serde(default)]
    pub given_name: Option<String>,
    /// Family name.
    #[serde(default)]
    pub family_name: Option<String>,
    /// Preferred username.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Picture URL.
    #[serde(default)]
    pub picture: Option<String>,
    /// Email address.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the email address is verified.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Every other claim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `/oauth/introspect` response. An inactive token carries only `active: false`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Introspection {
    /// Whether the token is active.
    pub active: bool,
    /// Space-delimited scopes.
    #[serde(default)]
    pub scope: Option<String>,
    /// The client id.
    #[serde(default)]
    pub client_id: Option<String>,
    /// The subject; absent for service tokens.
    #[serde(default)]
    pub sub: Option<String>,
    /// Expiry.
    #[serde(default, deserialize_with = "optional_timestamp")]
    pub exp: Option<i64>,
    /// Issue time.
    #[serde(default, deserialize_with = "optional_timestamp")]
    pub iat: Option<i64>,
    /// The token id.
    #[serde(default)]
    pub jti: Option<String>,
    /// The issuer.
    #[serde(default)]
    pub iss: Option<String>,
    /// The audiences.
    #[serde(default)]
    pub aud: Vec<String>,
}
