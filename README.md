# use-lock/client-rust

An async Rust client for [Lock](https://github.com/use-lock/lock). It has two parts:

- A handwritten auth layer for signing users in, obtaining tokens and validating the tokens a realm issues.
- Clients for the Admin, Management and Auth APIs, generated from Lock's OpenAPI specs behind the cargo features `admin`, `management` and `auth-api`.

It is built for Lock only and does not work with other OpenID Connect providers. HTTP runs on `reqwest` with rustls; there is no OpenSSL dependency.

Requires Rust 1.88 or newer.

## Installation

The crate is not published on crates.io yet. Use the Git repository:

```toml
[dependencies]
lock-client = { git = "https://github.com/use-lock/client-rust" }
# Generated API clients and test helpers are opt-in:
# lock-client = { git = "https://github.com/use-lock/client-rust", features = ["management", "testing"] }
```

## Configure a Realm

`lock_client::Realm` describes one client registered in one realm. The realm URL is the host of every protocol endpoint and the issuer of every token the realm mints.

```rust
use lock_client::Realm;

let realm = Realm::builder("https://id.example.com", "my-app")
    .client_secret("secret")                               // omit for public clients
    .redirect_uri("https://app.example.com/callback")      // only for the login flow
    .basic_auth(false)                                     // true for client_secret_basic clients
    .build()?;
```

A `Realm` is cheap to clone. Signing keys and client credentials tokens are kept in a `Cache`; the default is a process-local `MemoryCache`. Pass your own (Redis, a database) with `.cache(Arc<dyn Cache>)`. Other builder options are `.http_client(reqwest::Client)`, `.leeway(..)`, `.jwks_ttl(..)` and `.jwks_refresh_cooldown(..)`.

## Sign Users In

The login flow uses an authorization code with PKCE, a `state` and a `nonce`. Store the `AuthorizationRequest` from `begin()` (it implements `Serialize` and `Deserialize`, so it fits in a session) and pass it to `complete()` in the callback.

```rust
let auth = realm.authorization()?;
let request = auth.begin(&["openid", "profile", "email"])?;
// Store `request`, then redirect the browser to `request.url`.

// In the callback, pass the raw query string (or a HashMap of the parameters):
let tokens = auth.complete(&request, "code=...&state=...").await?;

tokens.access_token;
tokens.refresh_token;
tokens.claims.as_ref().map(|claims| claims.sub.as_str());
```

`complete()` checks the callback (`error`, `state`, the RFC 9207 `iss`), exchanges the code and validates the ID token: signature, issuer, audience, `azp`, nonce, expiry. Every failure is a `lock_client::Error`.

A failed request to Lock is `Error::Provider`, which carries the HTTP `status()` (`None` when no response arrived) and the OAuth `error()` code. `is_transient()` is true when retrying may help (no response, 5xx, 429) and false for a rejection such as `invalid_grant`, so a client can keep its session through an outage.

To log out at the provider, redirect to the logout URL:

```rust
let url = realm.authorization()?.logout_url(Some(&id_token), Some("https://app.example.com"), None)?;
```

## Obtain Tokens

```rust
let tokens = realm.tokens();

tokens.refresh(&refresh_token, None).await?;
tokens.exchange(&access_token, "https://api.example.com", None).await?;
tokens.client_credentials(Some("https://id.example.com/api"), None).await?;
tokens.userinfo(&access_token).await?;
tokens.introspect(&access_token).await?;
tokens.revoke(&refresh_token).await?;
```

Grants return a `TokenSet` with `expires_in()`, `is_expired(skew)` and `has_scope(..)`. Client credentials tokens are cached until 30 seconds before they expire.

## Validate Tokens

```rust
let claims = realm.id_tokens().validate(&id_token, &expected_nonce).await?;

// Lock's access tokens are addressed to the realm's resource identifiers, not to the client id.
let claims = realm.access_tokens().validate(&access_token, &["https://api.example.com"]).await?;
```

The signing keys come from the realm's JWKS. A token with an unknown `kid` refetches the key set once, so rotated keys are picked up; the refetch is rate limited (10 seconds by default) so forged `kid`s cannot flood Lock. Only RS256 is accepted.

A signature check cannot see a revocation. Where that matters, use `tokens.introspect(..)`.

To handle back-channel logout, validate the logout token and reject a `jti` that has already been used:

```rust
let logout = realm.logout_tokens().validate(&logout_token).await?;

if let Some(jti) = &logout.jti {
    if !realm.logout_token_replay().consume(jti, logout.exp).await {
        // Replayed logout token.
    }
}
// End the local sessions whose provider session id is `logout.sid`.
```

The replay check is only as atomic as `Cache::add`; override it with an atomic operation (Redis `SET NX`) when deliveries can race.

## Admin and Management APIs

The generated clients live in `lock_client::{admin, management, auth_api}` (features `admin`, `management`, `auth-api`). Each is a module of functions taking a `Configuration` and a parameter struct. The Admin and Management APIs are served under `/api` of the master realm. Authenticate with a client credentials token whose `resource` is `{issuer}/admin-api` for the Admin API or `{issuer}/api` for the Management API.

```rust
use lock_client::management::apis::{clients_api, configuration::Configuration};

let token = realm.tokens().client_credentials(Some("https://id.example.com/api"), None).await?;

let config = Configuration {
    base_path: "https://id.example.com/api".into(),
    oauth_access_token: Some(token.access_token),
    ..Configuration::default()
};

let clients = clients_api::list_clients(&config, clients_api::ListClientsParams {
    realm: "my-realm".into(),
    sort: None, filter_name: None, filter_client_id: None, filter_revoked: None,
    filter_token_endpoint_auth_method: None, page: None, per_page: None,
}).await?;
```

The Auth API client covers Lock's protocol endpoints (discovery, token, introspection, userinfo, logout). Use the handwritten auth layer to sign users in; use the generated Auth API client for raw access.

## Testing

With the `testing` feature, `lock_client::testing::FakeProvider` signs ID, access and logout tokens with an embedded RSA key and serves the matching JWKS (`jwks()`), so a fake authorization server in your tests only has to hand tokens out. The keys are public: never use them outside tests.

## Development

```bash
make check             # rustfmt, Clippy (-D warnings) and tests with every feature
make sync-openapi      # download Lock's specs from GitHub and regenerate the clients
make check-generated   # confirm src/admin, src/management and src/auth_api match the specs
```

`make sync-openapi` reads the specs from `use-lock/lock` at `main`. Set `LOCK_REF` to use another branch, tag or commit. The clients are generated with [OpenAPI Generator](https://openapi-generator.tech) (its `rust` target with `reqwest`) because Lock's specs are OpenAPI 3.1 and the Rust-native alternative, `progenitor`, only supports OpenAPI 3.0. It is also the generator `client-php` uses, with the same operation names. Never edit the generated modules by hand. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
