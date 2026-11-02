//! A Rust client for [Lock](https://github.com/use-lock/lock), a self-hosted identity provider.
//!
//! The crate has two parts:
//!
//! - A handwritten auth layer: sign users in with the authorization code flow and PKCE, obtain
//!   tokens, and validate the tokens a realm issues. Start at [`Realm`].
//! - Clients for the Admin, Management and Auth APIs, generated from Lock's OpenAPI specs
//!   behind the cargo features `admin`, `management` and `auth-api`.
//!
//! It is built for Lock only and does not work with other OpenID Connect providers.
//!
//! ```no_run
//! # async fn run() -> Result<(), lock_client::Error> {
//! use lock_client::Realm;
//!
//! let realm = Realm::builder("https://id.example.com", "my-app")
//!     .client_secret("secret")
//!     .redirect_uri("https://app.example.com/callback")
//!     .build()?;
//!
//! let request = realm.authorization()?.begin(&["openid", "profile", "email"])?;
//! // Store `request`, redirect the browser to `request.url`, and in the callback:
//! let tokens = realm.authorization()?.complete(&request, "code=abc&state=xyz").await?;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod authorization;
mod cache;
mod claims;
mod error;
mod jwks;
mod jwt;
mod realm;
mod token_set;
mod tokens;
mod validate;

#[cfg(feature = "testing")]
pub mod testing;

/// The generated Admin API client: realms.
#[cfg(feature = "admin")]
pub mod admin;
/// The generated Auth API client: OAuth, OpenID Connect, userinfo and discovery endpoints.
#[cfg(feature = "auth-api")]
pub mod auth_api;
/// The generated Management API client: clients, resources and social providers of a realm.
#[cfg(feature = "management")]
pub mod management;

pub use authorization::{Authorization, AuthorizationRequest, AuthorizeOptions, CallbackParams};
pub use cache::{Cache, MemoryCache};
pub use claims::{AccessTokenClaims, IdTokenClaims, Introspection, LogoutToken, UserInfo};
pub use error::{Error, ProviderError, Result, TokenError};
pub use realm::{ProviderMetadata, Realm, RealmBuilder};
pub use token_set::TokenSet;
pub use tokens::Tokens;
pub use validate::{
    AccessTokenValidator, IdTokenValidator, LogoutTokenReplay, LogoutTokenValidator,
};
