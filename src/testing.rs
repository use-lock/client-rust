//! An in-process token signer for tests of applications that use this crate (feature
//! `testing`). It signs ID, access and logout tokens the way Lock does and serves the matching
//! JWKS, so a fake authorization server only has to hand them out.
//!
//! The RSA keys are embedded and public: never trust them anywhere but in tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::PublicKeyComponents;
use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use crate::jwt::b64_encode;
use crate::token_set::now;

const KEY_1: &str = "MIIEowIBAAKCAQEA12wsGljcs9fe9ByoGVVjGZxs38PqHlUSjBXXSuvVUIuQfPJ4xVShnlpKzoLpP8eIcWTG1J52LEUOMt78siFAhS0uinghzND3HHhqly/Z4thm0M+M58tp1u7LOmykPIJi1RcBYZnGY22xx1bVYWj+GVuivNKQZQa3j+kkgNXLCrEbzlXOaOutKaK1+emT9MHYh1bSUo4PgldRjwpY8ybseIBY9wl/HIPas3o8W390Jh8ewEFj4fL7uS8q1KMbHCSuqihB6D4bSh2zabP0F9WGP4C+HbxlsP0QEGVvcvi2m+xsQKJzfYvQ02EmDhAQP9mUa07dJaiRLf1Qt4gZSpeCJQIDAQABAoIBAE+70QMbeuzx7KrL5Igj658yH7Ye7Iu3jzrcZqhra7P5REyK7pqTPZK/9spC+BRMRTs7QsC1uiWelafMkxlXZ2sjkwNbfZ8yhRQ7mbBF3M6yrDODbrLovk74aa5BQfTHic83SaKXaS+qDVAr2qTIWKyIF07uXNWXy99vOryY5SMaRohSml6uYTElacv0QnNsikQxl2kICcgo/zutdo+oygXI3W3ojt8XLo9at/Tq+QmUO6umbKEHPf+VIkvXNVUrR6sSDBwTiEiRSlG0o97WiQl8vOky+qSH8atF4WMTfsnPyZBjAvr+d/1ysE2qoz6RrfsDLnQS5cEfDqipf4mjC40CgYEA9/Tnaombr3zr3v56DzccqPa8eUep6SSjHo2OaZ4hK1LF5gQeVqgV9lJ3/Y2qB1ZFFUMKgKZyaWXS+Ym0M71JmW5SL2lSdMdsqtaTpe8EiZsKhAC3sKQBjutUpUSAha0gahCyfM7fslpjqag4llbElrTIF7k8UTjZqsol5St8D88CgYEA3mkYwB5qWEBKRmH2ukhnoS2Bb1CSf4rVawHFs9Gay+qmb+FTZheDqwDs5Fo9gXL0oTBG+qAG83Pn/M9FTgLqm+0j/5/iI0ZW9ZFPt4A/xRkqoIFtURTDzNgHVlhWS1MCIl/CrIr27x6HE5ilymFB3AID2SKTQglUk8R0cuH2t8sCgYA1s9MTHe6cGWA0kcT52qPYbGfxlHXWStsRWPNJKLhiW7EE2kt/1TO8f6wBPFdg82xO6JAzwNjyvtzssshWlF6GXoBqSFNVe4OrlIGx5IyFCRFD+avPFBZKT+mrSaTUTuTAVBF0OpH0XONM8WQgG3bEdS8JBFNt+/QYq2N9uOdLvQKBgBUBvDK5LLY1LE7FhfZGTHNuxuDqrUuao1m+CxxW2dYUza+XircD1Y3bQoS2+UQ2xWBMHQgjAUURV4ILWbJqmBouJc5JHaTTSfdbyDm+xUcqf1o1n0ufOHcqmFbRdSUcLAFvJgYCAhzHt15kdpRM51mOXyqtF1ePZgum7JDFQvZNAoGBALpqckHNnaNiqR/PbK4oO9SkFQt8lScjuUEobHXNofudpfLNCbjMY5DRHXfVMcm8/ZJB9nyZXNBQJvB3Wi+jJDCzU8CQZ6kAkeQh8D24+inpYubQecgTDo9qG1KIBEDYQtM3owIExR1ufq+o5KYPdwC4UiKJzhv5kwaRnNhK7jua";
const KEY_2: &str = "MIIEpAIBAAKCAQEA29RGculca89PJrxcJLHTaD6MkXsvCwUpLkXq61I+5wlQqf8gP/Zl3kKImG+kfEITNtf1OO6ZW2FOPNUc4bek4e/NwOJKts6CorOVK2LBJcqXs6nZUR7/sXqM1z/uM/JYAKZ/N/MR4Bx3SpHi41DoEUP+dFVxlJBMUQ4vsTSc1WowJ+XcMWAHo8bAQm0+NqWnXt5P98BK1564sbmhXZJ2UgvttVz1O15xv/08iQOCtHTks6y6WDUGhCQT00dYNWU8MUMDrN87Kc7ijtMK/E7BUhHA1mf/u/eSY8M8CT3WmAH/STS+tYnYVLRCXgyH9B5eC2IbUuJ/hmDLAa/g1Ch+EwIDAQABAoIBAQChDV4npgxN9+3XRTyErbtiriCyHPuUKU3IVvULPpBTF6H/SajI864iLcCBXZm2Z3pIPeOsuDGmnx2At+mW/MJRvSyS2bc/QwC2TrdEt+8lzs1hlVhfdESENHKm6HGNoUkUAOdHiE9aT8Cd40/ElmvO6m+rr0WtQCKJZ8lNHGyidPQFIENgheIy1cACik7X6XueUrlSDeaM08OzvycfSKgSE3eKPRiBJMPmq188jCykMTw9Q6wVSSfi84vT/0f9PNNwQTb+tBYVnYLMbLj9lmA93eUUdOjGdR5ziiTw48Gjw5y3dvKM2S6aG53+UjcvWhHCGptXqiGnZi2XlBUOMNcBAoGBAO1BKLWdqRcWf9BIFjE9K9kGQBBI7wp4zJBpQemnj6f4s1ybZGs1t8wVoe6jqBxmD2xv825xkvhsMAvWmS5urnDQCPyxdHzd/lzokK8CyLG6IHU/n92Lzx6ePNdpjAA7xj+neSJdICNpdhoaF/MF4aoXUXdfrg/qDrCP0eMhrKNTAoGBAO0yqXEW+eyc+WB6E7wkweekIrlZk7rsOopDL0PI/kcJBRV4QS+de4oaacZ1YdWGcdZTOqYewmbroLvnrYi7gJaGg34Vc5x5EqUC5WXDHyBjKEAMlQb3qb412gkSWHPdExCFD3KRDyThHzYLCD98YCn8w7drk+6H4SvDglLdliJBAoGBANtAX/KWZHClpjBAreGK+j5w/DsQa3dt8v1xiCv5YVSFDJwELmS1G8lKJH94Vh8IYjB/tKLX6k4RDMWj56N1PVebqPJ8u325WRtbAHn7RKSZsO0pgv8l+J3+9ZLMQ0jj9G1WwybykISpLS8p9f/r64NYUTzT+vNSBYk9H2Wa9QNpAoGAUEL0UvATYZ08RQkJ5IALnPZNSaql8no81MwnEijQ4fiLX9hxNktzoieN4zmVAUuc+YjwL4X5Ahp5KRwb/Eh2GnkpxWA83pWZWXzBYs3DmpHy7LlVNCZZqaNPRAKRK6OC7/QWZg3vser7RK42/ER5xbth/o7IX85awxRE5QVV6AECgYAkUg/y8Dj9H34z85WAk/iW5wLeBY7xY2BHw+cmRG/zO4R7tlqV5fegBSU89mmewLsoaBONBG7v6uXSml9SNzwyEHP44gHYidiuDnYu4B9HTOzDt7ttSyWRt+FhwM9HTaeZhm4D2hqfYbFy+KviaQ4HQoAW5vEnfjaItBWwzaBp1A==";
const KEY_3: &str = "MIIEogIBAAKCAQEA6AZDi+6Ig9FVTyyRLQLH3TqVQfjUOJTm4OhVHdT7Yb3sg93864UoWNqbrr6gcBbP57sq7W0Zz5RZNJ5XriaG7/FJyyEA8wSnHAUkxNp0njIEdNncJtQkkK480kN9rjq1YEbN7trlTeBI42XlpkSmnJYW04BDPsuWakGqMEv/X03lrt+LEef4QOjhR+H5s56C2hp2dE4bXaIWWMXetSvLHCglrgR/bdj7JCiSl5HnWbG/ecBbXOmS3/SQ1Ptcllg2/EOZ9y91st9ozLJEYT2BxBV/nmQ7n29zgs+iYQS8Rco9c75Pt/l96an+GMoJXjOwf+o6c5414OcVDa5D66LNZwIDAQABAoIBAFnSivWyC0FUmb0D2NPe/rajRkL67FVXN6Yb60+YMxUcrGJEXvRiYUM8pgZZH80k16mzKKQvl01n9bzMC8+MdLKQ62tqxG5P/812JEzc8UaIwHboHDUf7WPhQAR6Qj5f1fWGk5SDQ0AJss3tlaDvdLyr0fxg7Cd0My/Bafw2f49J4QMbbDRarj6q+9lUQWGP6iouzSdm/SXKSVHTCrB6p/HL2lfBo33Df+bh1MUzfp7itFZH4VI/L74cThFljtlQLwgfwrys2BGWlNe87jmNnxD8R4Pz0+Mr65tjX5Fs/vVeQzQgHcJLjYkFfS+yTkx5wJluvfc/Fk5IMh7bvpAY+JECgYEA+JDuNKD7AkLjhcG+C1tDQrMyNg9LjAkaaDARPBGdYoMc34AFTuZO6W+xobKQ92fdQWy+yjQNC/zAa69a3QvF8qTtvHT4TuEtbN28+4l16hYVtZ//eiLNrOuQ/IYCHs1gSmEUKFIowlUV7yHBJj6/mwsxrPglSMM1WojLGqqiac8CgYEA7vav7fBEEGexpLxasZ0bxoh4Zcl6LzkCbV5KlNxFKLtksU/Zj3weBBRIz9QUYg0znwF4g9lqao+n5hX7EN9jxxPalXhKdPa9ePqTBqVZn2Hs2sqq3VNs3VnvvhL8O/RUgxPC4uQKl41naC5iignE2wgOMdzkr0ThOCmXj4fHgOkCgYBuPoGYEAokP5x/96UdjlWvoKDVf0Unj+YJbcBHHxzp03Mb4cD49IbtXB+xsuw+/u8QFHYuYpWiynBhkn2/anhaHTJgEpULDy5BibtG6PnGYBMy4grClesZFcXRanJITRi3BIWXOJFhV7GJxTPQjaYX0wguSkTnF8VzKRbD9ghg2wKBgFqJQDKH+2Gzx8xASKROf/2CKwt1gENv+Alz1hH8On+qMAY12JnSTpUBEm0bTvWvRsWRixV5RCZHczdrUIod+PGuBfznbF5QNY0mcpnr/76xHUnvyzi7qN1ce8ap7sLQWUyoKghImfK9clY4bMEb3meV77rYlBQLpsDekTuiF+YxAoGAd99YoX+IK2rX5F35G+E7gxGgAXQmf8RmHcG7RQ53kdyS3Ml26ov04S3uoJ0oiCo3J/oj8FgcwDWQ68Zk/zFuNos19U+iXjGyxDeBHjyR9xdEETTPWryT+EuFaEMTnPvRlx35aenhqV/mqYmLn7C7F/pwc0Puk1AOuCJTWE/NvUk=";

/// Signs tokens with a fixed test key.
pub struct FakeProvider {
    issuer: String,
    kid: String,
    key: RsaKeyPair,
}

impl FakeProvider {
    fn with(issuer: &str, kid: &str, pkcs8: &str) -> Self {
        let der = STANDARD
            .decode(pkcs8)
            .expect("embedded test key is valid base64");
        Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            kid: kid.to_owned(),
            key: RsaKeyPair::from_der(&der).expect("embedded test key is valid PKCS#1"),
        }
    }

    /// The realm's first key, `test-key-1`.
    pub fn new(issuer: &str) -> Self {
        Self::with(issuer, "test-key-1", KEY_1)
    }

    /// The key a realm rotates to, `test-key-2`.
    pub fn rotated(issuer: &str) -> Self {
        Self::with(issuer, "test-key-2", KEY_2)
    }

    /// An attacker's key under the first key's `kid`: its tokens must fail signature checks.
    pub fn forged(issuer: &str) -> Self {
        Self::with(issuer, "test-key-1", KEY_3)
    }

    /// The `kid` header of the tokens.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The key set document (`/.well-known/jwks.json`) with this provider's public key.
    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.jwk()] })
    }

    /// This provider's public key as one JWK.
    pub fn jwk(&self) -> Value {
        let public = PublicKeyComponents::<Vec<u8>>::from(self.key.public_key());
        json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
            "n": b64_encode(&public.n), "e": b64_encode(&public.e),
        })
    }

    /// Signs `claims` with RS256 and the given `typ` header.
    pub fn sign(&self, typ: Option<&str>, claims: &Value) -> String {
        let mut header = json!({ "alg": "RS256", "kid": self.kid });
        if let Some(typ) = typ {
            header["typ"] = json!(typ);
        }
        self.sign_with_header(&header, claims)
    }

    /// Signs with an arbitrary header, for malformed-token tests.
    pub fn sign_with_header(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64_encode(header.to_string()),
            b64_encode(claims.to_string())
        );
        let mut signature = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .expect("signing with an embedded key");
        format!("{input}.{}", b64_encode(signature))
    }

    /// Valid ID token claims for a login by `sub`; change fields, then [`sign`](Self::sign).
    pub fn id_token_claims(&self, client_id: &str, nonce: &str, sub: &str) -> Value {
        let now = now();
        json!({
            "iss": self.issuer, "sub": sub, "aud": [client_id], "azp": client_id,
            "exp": now + 3600, "iat": now, "nonce": nonce, "sid": "session-1", "name": "Test User",
        })
    }

    /// A valid signed ID token.
    pub fn id_token(&self, client_id: &str, nonce: &str, sub: &str) -> String {
        self.sign(None, &self.id_token_claims(client_id, nonce, sub))
    }

    /// Valid JWT access token claims, as Lock mints them.
    pub fn access_token_claims(
        &self,
        client_id: &str,
        audience: &str,
        scope: &str,
        sub: &str,
    ) -> Value {
        let now = now();
        json!({
            "iss": self.issuer, "sub": sub, "aud": [audience], "client_id": client_id,
            "exp": now + 3600, "iat": now, "nbf": now, "jti": "access-1",
            "scope": scope, "scopes": scope.split(' ').collect::<Vec<_>>(),
        })
    }

    /// A valid signed `at+jwt` access token.
    pub fn access_token(&self, client_id: &str, audience: &str, scope: &str, sub: &str) -> String {
        self.sign(
            Some("at+jwt"),
            &self.access_token_claims(client_id, audience, scope, sub),
        )
    }

    /// Valid back-channel logout token claims.
    pub fn logout_token_claims(&self, client_id: &str, sid: &str, sub: &str, jti: &str) -> Value {
        let now = now();
        json!({
            "iss": self.issuer, "sub": sub, "aud": [client_id], "iat": now, "exp": now + 120,
            "jti": jti, "sid": sid,
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        })
    }

    /// A valid signed `logout+jwt` token.
    pub fn logout_token(&self, client_id: &str, sid: &str, sub: &str, jti: &str) -> String {
        self.sign(
            Some("logout+jwt"),
            &self.logout_token_claims(client_id, sid, sub, jti),
        )
    }
}
