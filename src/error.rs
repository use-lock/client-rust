//! Error types of the auth layer.

use std::error::Error as StdError;

/// Everything that can go wrong in the auth layer.
///
/// [`Error::Provider`] covers failed requests to Lock. [`Error::is_transient`] tells an outage
/// from a rejection, so a client can keep a session through an outage.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The realm configuration is incomplete or invalid.
    #[error("invalid realm configuration: {0}")]
    Config(String),

    /// The provider redirected back with an authorization error.
    #[error("the provider returned an authorization error [{error}]")]
    Authorization {
        /// The OAuth `error` code.
        error: String,
        /// The `error_description`, when the provider sent one.
        description: Option<String>,
    },

    /// The callback `state` is missing or differs from the stored request.
    #[error("the OIDC state parameter did not match")]
    StateMismatch,

    /// The callback `iss` parameter (RFC 9207) names another issuer.
    #[error("the callback issuer does not match")]
    CallbackIssuerMismatch,

    /// The callback carries no authorization code.
    #[error("the provider did not return an authorization code")]
    MissingCode,

    /// The token response carries no `id_token`.
    #[error("the token response did not include an id_token")]
    MissingIdToken,

    /// A token failed validation.
    #[error(transparent)]
    Token(#[from] TokenError),

    /// A request to the provider failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

impl Error {
    /// Whether retrying may succeed: nothing came back, the provider failed or it throttled the
    /// request. Only [`Error::Provider`] can be transient.
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Provider(error) if error.is_transient())
    }
}

/// A token that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// The token is not a well-formed JWT.
    #[error("the {name} could not be parsed")]
    Malformed {
        /// The kind of token, such as `id_token`.
        name: &'static str,
    },
    /// The token is signed with an algorithm other than RS256 (`none`, `HS256`, ...).
    #[error("the {name} is not signed with RS256")]
    UnsupportedAlgorithm {
        /// The kind of token.
        name: &'static str,
    },
    /// The `typ` header is not the one this token kind carries.
    #[error("the {name} has an unexpected typ header")]
    UnexpectedType {
        /// The kind of token.
        name: &'static str,
    },
    /// The token has no `kid` header.
    #[error("the {name} has no kid header")]
    MissingKeyId {
        /// The kind of token.
        name: &'static str,
    },
    /// No key of the realm matches the `kid`, even after refreshing the key set.
    #[error("no JWKS key matches the token kid [{kid}]")]
    UnknownKey {
        /// The `kid` of the token.
        kid: String,
    },
    /// The signature does not verify against the realm key.
    #[error("the {name} signature is invalid")]
    InvalidSignature {
        /// The kind of token.
        name: &'static str,
    },
    /// The `iss` claim is not the realm's issuer.
    #[error("the {name} issuer does not match")]
    IssuerMismatch {
        /// The kind of token.
        name: &'static str,
    },
    /// The `aud` claim does not include this client (or an accepted audience).
    #[error("the {name} audience does not include this client")]
    AudienceMismatch {
        /// The kind of token.
        name: &'static str,
    },
    /// The `azp` claim names another client.
    #[error("the {name} azp does not match this client")]
    AuthorizedPartyMismatch {
        /// The kind of token.
        name: &'static str,
    },
    /// The `nonce` claim differs from the one of the authorization request.
    #[error("the {name} nonce does not match")]
    NonceMismatch {
        /// The kind of token.
        name: &'static str,
    },
    /// The token expired.
    #[error("the {name} has expired")]
    Expired {
        /// The kind of token.
        name: &'static str,
    },
    /// The token is not valid yet (`nbf`).
    #[error("the {name} is not yet valid")]
    NotYetValid {
        /// The kind of token.
        name: &'static str,
    },
    /// The token claims to be issued in the future (`iat`).
    #[error("the {name} was issued in the future")]
    IssuedInFuture {
        /// The kind of token.
        name: &'static str,
    },
    /// A logout token older than its validity window.
    #[error("the {name} was issued too long ago")]
    IssuedTooLongAgo {
        /// The kind of token.
        name: &'static str,
    },
    /// A required claim is missing or has the wrong type.
    #[error("the {name} is missing the {claim} claim")]
    MissingClaim {
        /// The kind of token.
        name: &'static str,
        /// The claim.
        claim: &'static str,
    },
    /// The logout token lacks the back-channel logout event.
    #[error("the logout token is missing the back-channel logout event")]
    MissingLogoutEvent,
    /// The logout token carries a `nonce`, which RFC-forbidden.
    #[error("a logout token must not contain a nonce")]
    LogoutTokenNonce,
}

/// A request to the provider failed: it rejected the request, failed itself, or no response
/// arrived.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ProviderError {
    message: String,
    status: Option<u16>,
    error: Option<String>,
    #[source]
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl ProviderError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: None,
            error: None,
            source: None,
        }
    }

    pub(crate) fn with_status(mut self, status: Option<u16>) -> Self {
        self.status = status;
        self
    }

    pub(crate) fn with_error(mut self, error: Option<String>) -> Self {
        self.error = error;
        self
    }

    pub(crate) fn with_source(mut self, source: impl StdError + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// The HTTP status, or `None` when no response arrived.
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// The OAuth error code of the response, such as `invalid_grant`.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Whether retrying may succeed: nothing came back, the provider failed, or it throttled the
    /// request. A rejection stays a rejection.
    pub fn is_transient(&self) -> bool {
        match self.status {
            None => true,
            Some(status) => status >= 500 || status == 429,
        }
    }
}

/// The result type of the auth layer.
pub type Result<T, E = Error> = std::result::Result<T, E>;
