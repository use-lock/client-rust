#![allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)]

mod support;

use std::collections::HashMap;
use std::time::Duration;

use lock_client::testing::FakeProvider;
use lock_client::{AuthorizationRequest, Error, Realm, TokenError};
use serde_json::json;
use support::{CLIENT_ID, Fake, REDIRECT, SECRET};

fn realm(fake: &Fake, basic: bool) -> Realm {
    Realm::builder(&fake.url, CLIENT_ID)
        .client_secret(SECRET)
        .redirect_uri(REDIRECT)
        .basic_auth(basic)
        .jwks_refresh_cooldown(Duration::ZERO)
        .build()
        .unwrap()
}

fn token_error(error: Error) -> TokenError {
    match error {
        Error::Token(error) => error,
        other => panic!("expected a token error, got {other:?}"),
    }
}

async fn login(fake: &Fake, realm: &Realm) -> Result<lock_client::TokenSet, Error> {
    let auth = realm.authorization().unwrap();
    let request = auth.begin(&["openid", "profile"]).unwrap();
    let callback = fake.authorize(&request.url);
    auth.complete(&request, callback.as_str()).await
}

#[tokio::test]
async fn full_login_with_post_and_basic_client_authentication() {
    for basic in [false, true] {
        let fake = Fake::start().await;
        let realm = realm(&fake, basic);
        let tokens = login(&fake, &realm).await.unwrap();

        let claims = tokens.claims.as_ref().unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.name.as_deref(), Some("Test User"));
        assert_eq!(claims.aud, [CLIENT_ID]);
        assert!(tokens.has_scope("profile"));
        assert!(!tokens.is_expired(30) && tokens.expires_in() > 800);
        assert_eq!(tokens.refresh_token.as_deref(), Some("refresh-1"));
        // The secret contains characters that must be form-encoded before the Basic header.
        assert_eq!(fake.with(|r| r.last_basic.clone()).is_some(), basic);
    }
}

#[tokio::test]
async fn authorization_request_survives_a_session_round_trip() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let auth = realm.authorization().unwrap();
    let request = auth.begin(&["openid"]).unwrap();

    let stored = serde_json::to_string(&request).unwrap();
    let restored: AuthorizationRequest = serde_json::from_str(&stored).unwrap();
    let callback = fake.authorize(&restored.url);

    assert!(auth.complete(&restored, callback.as_str()).await.is_ok());
    assert_eq!(request.state.len(), 32);
    assert!(!format!("{request:?}").contains(&request.code_verifier));
}

#[tokio::test]
async fn callback_rejections() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let auth = realm.authorization().unwrap();
    let request = auth.begin(&["openid"]).unwrap();
    let good = fake.authorize(&request.url);

    let wrong_state = good.replace(&request.state, "forged");
    assert!(matches!(
        auth.complete(&request, wrong_state.as_str()).await,
        Err(Error::StateMismatch)
    ));
    assert!(matches!(
        auth.complete(&request, "code=x").await,
        Err(Error::StateMismatch)
    ));

    let denied = format!(
        "error=access_denied&error_description=no&state={}",
        request.state
    );
    assert!(
        matches!(auth.complete(&request, denied.as_str()).await, Err(Error::Authorization { error, .. }) if error == "access_denied")
    );

    let no_code = format!("state={}", request.state);
    assert!(matches!(
        auth.complete(&request, no_code.as_str()).await,
        Err(Error::MissingCode)
    ));

    let mut params: HashMap<String, String> = url::form_urlencoded::parse(good.as_bytes())
        .into_owned()
        .collect();
    params.insert("iss".into(), "https://evil.example".into());
    assert!(matches!(
        auth.complete(&request, params).await,
        Err(Error::CallbackIssuerMismatch)
    ));

    // None of the above consumed the code: the good callback still works.
    assert!(auth.complete(&request, good.as_str()).await.is_ok());
}

#[tokio::test]
async fn a_replayed_code_is_rejected_as_invalid_grant() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let auth = realm.authorization().unwrap();
    let request = auth.begin(&["openid"]).unwrap();
    let callback = fake.authorize(&request.url);

    auth.complete(&request, callback.as_str()).await.unwrap();
    let error = auth
        .complete(&request, callback.as_str())
        .await
        .unwrap_err();

    let Error::Provider(provider) = &error else {
        panic!("{error:?}")
    };
    assert_eq!(provider.status(), Some(400));
    assert_eq!(provider.error(), Some("invalid_grant"));
    assert!(!error.is_transient());
}

#[tokio::test]
async fn id_token_rejections() {
    type Tamper = Box<dyn Fn(&mut serde_json::Value) + Send + Sync>;
    let cases: Vec<(&str, Tamper, fn(&TokenError) -> bool)> = vec![
        (
            "wrong issuer",
            Box::new(|c| c["iss"] = json!("https://evil.example")),
            |e| matches!(e, TokenError::IssuerMismatch { .. }),
        ),
        (
            "wrong audience",
            Box::new(|c| {
                c["aud"] = json!(["other-app"]);
                c["azp"] = json!("other-app");
            }),
            |e| matches!(e, TokenError::AudienceMismatch { .. }),
        ),
        (
            "expired",
            Box::new(|c| c["exp"] = json!(1_000_000_000)),
            |e| matches!(e, TokenError::Expired { .. }),
        ),
        (
            "nonce mismatch",
            Box::new(|c| c["nonce"] = json!("someone-elses")),
            |e| matches!(e, TokenError::NonceMismatch { .. }),
        ),
        (
            "missing nonce",
            Box::new(|c| {
                c.as_object_mut().unwrap().remove("nonce");
            }),
            |e| matches!(e, TokenError::NonceMismatch { .. }),
        ),
        (
            "foreign azp",
            Box::new(|c| c["azp"] = json!("other-app")),
            |e| matches!(e, TokenError::AuthorizedPartyMismatch { .. }),
        ),
        (
            "multiple audiences without azp",
            Box::new(|c| {
                c["aud"] = json!([CLIENT_ID, "x"]);
                c.as_object_mut().unwrap().remove("azp");
            }),
            |e| matches!(e, TokenError::AuthorizedPartyMismatch { .. }),
        ),
        (
            "issued in the future",
            Box::new(|c| c["iat"] = json!(4_102_444_800_i64)),
            |e| matches!(e, TokenError::IssuedInFuture { .. }),
        ),
        (
            "not yet valid",
            Box::new(|c| c["nbf"] = json!(4_102_444_800_i64)),
            |e| matches!(e, TokenError::NotYetValid { .. }),
        ),
        ("no subject", Box::new(|c| c["sub"] = json!("")), |e| {
            matches!(e, TokenError::MissingClaim { claim: "sub", .. })
        }),
    ];

    for (name, tamper, expected) in cases {
        let fake = Fake::start().await;
        fake.with(|r| r.id_claims = Some(tamper));
        let error = token_error(login(&fake, &realm(&fake, false)).await.unwrap_err());
        assert!(expected(&error), "{name}: {error:?}");
    }
}

#[tokio::test]
async fn id_token_with_a_bad_signature_or_algorithm_is_rejected() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let validator = realm.id_tokens();
    let claims = fake.provider().id_token_claims(CLIENT_ID, "n", "user-1");

    // Signed by an attacker under the realm key's kid.
    let forged = FakeProvider::forged(&fake.url).sign(None, &claims);
    assert!(matches!(
        token_error(validator.validate(&forged, "n").await.unwrap_err()),
        TokenError::InvalidSignature { .. }
    ));

    // A tampered payload under a valid signature.
    let good = fake.provider().sign(None, &claims);
    let mut parts: Vec<&str> = good.split('.').collect();
    let evil = {
        use base64::Engine;
        let mut evil = claims.clone();
        evil["sub"] = json!("admin");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(evil.to_string())
    };
    parts[1] = &evil;
    assert!(matches!(
        token_error(validator.validate(&parts.join("."), "n").await.unwrap_err()),
        TokenError::InvalidSignature { .. }
    ));

    // `alg: none` and HS256 never get as far as a key lookup.
    for alg in ["none", "HS256"] {
        let token = fake
            .provider()
            .sign_with_header(&json!({ "alg": alg, "kid": "test-key-1" }), &claims);
        assert!(
            matches!(
                token_error(validator.validate(&token, "n").await.unwrap_err()),
                TokenError::UnsupportedAlgorithm { .. }
            ),
            "{alg}"
        );
    }
    let no_kid = fake
        .provider()
        .sign_with_header(&json!({ "alg": "RS256" }), &claims);
    assert!(matches!(
        token_error(validator.validate(&no_kid, "n").await.unwrap_err()),
        TokenError::MissingKeyId { .. }
    ));

    for garbage in ["", "a.b", "a.b.c", "a.b.c.d"] {
        assert!(
            matches!(
                token_error(validator.validate(garbage, "n").await.unwrap_err()),
                TokenError::Malformed { .. }
            ),
            "{garbage}"
        );
    }
    assert_eq!(
        fake.with(|r| r.jwks_hits),
        1,
        "only the signature checks looked up keys"
    );
}

#[tokio::test]
async fn unknown_kid_refetches_the_keys_and_picks_up_a_rotation() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let validator = realm.id_tokens();

    let first = fake.provider().id_token(CLIENT_ID, "n", "user-1");
    validator.validate(&first, "n").await.unwrap();
    validator.validate(&first, "n").await.unwrap();
    assert_eq!(
        fake.with(|r| r.jwks_hits),
        1,
        "known keys are served from the cache"
    );

    // The realm rotates: a token under an unpublished kid fails, once it is published it passes.
    let rotated = FakeProvider::rotated(&fake.url);
    let token = rotated.id_token(CLIENT_ID, "n", "user-1");
    let error = token_error(validator.validate(&token, "n").await.unwrap_err());
    assert_eq!(
        error,
        TokenError::UnknownKey {
            kid: "test-key-2".into()
        }
    );
    assert_eq!(fake.with(|r| r.jwks_hits), 2);

    fake.with(|r| r.jwks = json!({ "keys": [fake_key(&r.jwks), rotated.jwk()] }));
    validator.validate(&token, "n").await.unwrap();
    assert_eq!(fake.with(|r| r.jwks_hits), 3);
    // The retired key still verifies while it is published.
    validator.validate(&first, "n").await.unwrap();
}

fn fake_key(jwks: &serde_json::Value) -> serde_json::Value {
    jwks["keys"][0].clone()
}

#[tokio::test]
async fn the_key_refetch_is_rate_limited() {
    let fake = Fake::start().await;
    let realm = Realm::builder(&fake.url, CLIENT_ID)
        .jwks_refresh_cooldown(Duration::from_secs(60))
        .build()
        .unwrap();
    let validator = realm.id_tokens();
    let stranger = FakeProvider::rotated(&fake.url).id_token(CLIENT_ID, "n", "u");

    for _ in 0..5 {
        assert!(validator.validate(&stranger, "n").await.is_err());
    }
    assert_eq!(fake.with(|r| r.jwks_hits), 1);
}

#[tokio::test]
async fn refresh_keeps_the_old_refresh_token_when_none_is_returned() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let tokens = realm.tokens();
    fake.with(|r| r.refresh_tokens.push("refresh-1".into()));

    let first = tokens.refresh("refresh-1", None).await.unwrap();
    assert_eq!(first.refresh_token.as_deref(), Some("refresh-2"));
    let second = tokens.refresh("refresh-2", None).await.unwrap();
    assert_eq!(second.refresh_token.as_deref(), Some("refresh-2"));

    let error = tokens.refresh("revoked", None).await.unwrap_err();
    assert!(!error.is_transient());
    assert!(matches!(&error, Error::Provider(p) if p.error() == Some("invalid_grant")));
}

#[tokio::test]
async fn outages_are_transient_and_rejections_are_not() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);

    for (status, transient) in [
        (503, true),
        (500, true),
        (429, true),
        (400, false),
        (401, false),
    ] {
        fake.with(|r| r.token_status = Some(status));
        let error = realm.tokens().refresh("refresh-1", None).await.unwrap_err();
        assert_eq!(error.is_transient(), transient, "{status}");
    }

    let dead = Realm::builder("http://127.0.0.1:9", CLIENT_ID)
        .client_secret(SECRET)
        .build()
        .unwrap();
    let error = dead.tokens().refresh("x", None).await.unwrap_err();
    assert!(error.is_transient());
    assert!(matches!(&error, Error::Provider(p) if p.status().is_none()));
}

#[tokio::test]
async fn wrong_client_secret_is_a_rejection() {
    let fake = Fake::start().await;
    let realm = Realm::builder(&fake.url, CLIENT_ID)
        .client_secret("wrong")
        .build()
        .unwrap();
    let error = realm
        .tokens()
        .client_credentials(None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Provider(p) if p.status() == Some(401) && p.error() == Some("invalid_client"))
    );
}

#[tokio::test]
async fn client_credentials_tokens_are_cached_per_request_shape() {
    let fake = Fake::start().await;
    let realm = realm(&fake, true);
    let tokens = realm.tokens();

    let a = tokens
        .client_credentials(Some("https://id.example.com/api"), Some(&["b", "a", "a"]))
        .await
        .unwrap();
    let b = tokens
        .client_credentials(Some("https://id.example.com/api"), Some(&["a", "b"]))
        .await
        .unwrap();
    assert_eq!(a.access_token, b.access_token);
    assert_eq!(fake.with(|r| r.token_hits), 1);

    let other = tokens
        .client_credentials(Some("https://id.example.com/admin-api"), None)
        .await
        .unwrap();
    assert_ne!(a.access_token, other.access_token);
    assert_eq!(fake.with(|r| r.token_hits), 2);
}

#[tokio::test]
async fn access_token_validation() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let validator = realm.access_tokens();
    let provider = fake.provider();
    let api = "https://api.example.com";

    let token = provider.access_token(CLIENT_ID, api, "openid read", "user-1");
    let claims = validator.validate(&token, &[api]).await.unwrap();
    assert_eq!(claims.sub, "user-1");
    assert!(claims.has_scope("read") && !claims.has_scope("write"));
    assert_eq!(claims.client_id.as_deref(), Some(CLIENT_ID));

    let wrong_audience = validator
        .validate(&token, &["https://other.example.com"])
        .await
        .unwrap_err();
    assert!(matches!(
        token_error(wrong_audience),
        TokenError::AudienceMismatch { .. }
    ));

    // An ID token must not pass as an access token.
    let id_token = provider.id_token(CLIENT_ID, "n", "user-1");
    assert!(matches!(
        token_error(
            validator
                .validate(&id_token, &[CLIENT_ID])
                .await
                .unwrap_err()
        ),
        TokenError::UnexpectedType { .. }
    ));

    let mut expired = provider.access_token_claims(CLIENT_ID, api, "openid", "user-1");
    expired["exp"] = json!(1_000_000_000);
    let expired = provider.sign(Some("at+jwt"), &expired);
    assert!(matches!(
        token_error(validator.validate(&expired, &[api]).await.unwrap_err()),
        TokenError::Expired { .. }
    ));

    let forged = FakeProvider::forged(&fake.url).access_token(CLIENT_ID, api, "openid", "user-1");
    assert!(matches!(
        token_error(validator.validate(&forged, &[api]).await.unwrap_err()),
        TokenError::InvalidSignature { .. }
    ));
}

#[tokio::test]
async fn back_channel_logout_tokens() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let validator = realm.logout_tokens();
    let provider = fake.provider();

    let token = provider.logout_token(CLIENT_ID, "session-1", "user-1", "jti-1");
    let logout = validator.validate(&token).await.unwrap();
    assert_eq!(
        (
            logout.sid.as_str(),
            logout.sub.as_str(),
            logout.jti.as_deref()
        ),
        ("session-1", "user-1", Some("jti-1"))
    );

    let replay = realm.logout_token_replay();
    assert!(replay.consume("jti-1", logout.exp).await);
    assert!(
        !replay.consume("jti-1", logout.exp).await,
        "a replayed jti is refused"
    );
    assert!(replay.consume("jti-2", logout.exp).await);

    let mut with_nonce = provider.logout_token_claims(CLIENT_ID, "s", "u", "j");
    with_nonce["nonce"] = json!("n");
    let with_nonce = provider.sign(Some("logout+jwt"), &with_nonce);
    assert_eq!(
        token_error(validator.validate(&with_nonce).await.unwrap_err()),
        TokenError::LogoutTokenNonce
    );

    let mut no_event = provider.logout_token_claims(CLIENT_ID, "s", "u", "j");
    no_event["events"] = json!({});
    assert_eq!(
        token_error(
            validator
                .validate(&provider.sign(Some("logout+jwt"), &no_event))
                .await
                .unwrap_err()
        ),
        TokenError::MissingLogoutEvent
    );

    let mut other_client = provider.logout_token_claims("other-app", "s", "u", "j");
    other_client["aud"] = json!(["other-app"]);
    assert!(matches!(
        token_error(
            validator
                .validate(&provider.sign(Some("logout+jwt"), &other_client))
                .await
                .unwrap_err()
        ),
        TokenError::AudienceMismatch { .. }
    ));

    let mut old = provider.logout_token_claims(CLIENT_ID, "s", "u", "j");
    old["iat"] = json!(1_000_000_000);
    old["exp"] = json!(4_102_444_800_i64);
    assert!(matches!(
        token_error(
            validator
                .validate(&provider.sign(Some("logout+jwt"), &old))
                .await
                .unwrap_err()
        ),
        TokenError::IssuedTooLongAgo { .. }
    ));

    let mut no_sid = provider.logout_token_claims(CLIENT_ID, "s", "u", "j");
    no_sid.as_object_mut().unwrap().remove("sid");
    assert!(matches!(
        token_error(
            validator
                .validate(&provider.sign(Some("logout+jwt"), &no_sid))
                .await
                .unwrap_err()
        ),
        TokenError::MissingClaim { claim: "sid", .. }
    ));

    // An ID token has no logout event and the wrong typ-less shape.
    let id_token = provider.id_token(CLIENT_ID, "n", "user-1");
    assert!(validator.validate(&id_token).await.is_err());
}

#[tokio::test]
async fn userinfo_introspection_and_metadata() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let tokens = realm.tokens();

    let info = tokens.userinfo("good").await.unwrap();
    assert_eq!(info.sub, "user-1");
    assert_eq!(info.name.as_deref(), Some("Test User"));
    assert_eq!(info.preferred_username, None);
    assert_eq!(info.extra["locale"], "de");
    assert!(
        matches!(tokens.userinfo("bad").await.unwrap_err(), Error::Provider(p) if p.status() == Some(401))
    );

    assert!(tokens.introspect("good").await.unwrap().active);
    assert!(!tokens.introspect("revoked").await.unwrap().active);

    assert_eq!(
        realm.metadata().await.unwrap().claims_supported,
        ["sub", "name", "email"]
    );
}

#[test]
fn logout_url_and_configuration() {
    let realm = Realm::builder("https://id.example.com/", CLIENT_ID)
        .redirect_uri(REDIRECT)
        .build()
        .unwrap();
    assert_eq!(realm.url(), "https://id.example.com");

    let url = realm
        .authorization()
        .unwrap()
        .logout_url(Some("idt"), Some("https://app.example.com"), Some("s"))
        .unwrap();
    assert_eq!(
        url,
        "https://id.example.com/oauth/logout?id_token_hint=idt&client_id=my-app&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com&state=s"
    );

    let no_redirect = Realm::builder("https://id.example.com", CLIENT_ID)
        .build()
        .unwrap();
    assert!(matches!(no_redirect.authorization(), Err(Error::Config(_))));
    assert!(matches!(
        Realm::builder("ftp://x", CLIENT_ID).build(),
        Err(Error::Config(_))
    ));
    assert!(matches!(
        Realm::builder("https://x", CLIENT_ID)
            .basic_auth(true)
            .build(),
        Err(Error::Config(_))
    ));
}

/// Lock builds its tokens with lcobucci/jwt's default claims formatter, which writes `iat` and
/// `exp` as floats with microseconds (`1762085339.123456`) unless the microseconds are zero.
#[tokio::test]
async fn id_token_with_fractional_timestamps_is_accepted() {
    let fake = Fake::start().await;
    let realm = realm(&fake, false);
    let mut claims = fake.provider().id_token_claims(CLIENT_ID, "n", "user-1");
    let now = claims["iat"].as_i64().unwrap() as f64;
    claims["iat"] = json!(now + 0.123456);
    claims["exp"] = json!(now + 3600.654321);
    claims["auth_time"] = json!(now - 5.5);
    let token = fake.provider().sign(None, &claims);

    let validated = realm.id_tokens().validate(&token, "n").await.unwrap();
    assert_eq!(validated.sub, "user-1");
    assert_eq!(validated.iat, now as i64);
    assert_eq!(validated.exp, now as i64 + 3600);
    assert_eq!(validated.auth_time, Some(now as i64 - 6));
}
