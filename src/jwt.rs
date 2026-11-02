//! Minimal RS256 JWT parsing and verification.
//!
//! Lock signs every token with RS256. Anything else, including `none` and the HMAC family, is
//! rejected before any key is looked up, so algorithm confusion is not possible.

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use crate::error::TokenError;

pub(crate) fn b64_encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn b64_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

/// A parsed, not yet verified, JWT.
pub(crate) struct Jwt {
    pub(crate) header: Map<String, Value>,
    pub(crate) claims: Map<String, Value>,
    signing_input: String,
    signature: Vec<u8>,
}

impl Jwt {
    /// Parses a compact JWS and checks that it claims RS256.
    pub(crate) fn parse(token: &str, name: &'static str) -> Result<Self, TokenError> {
        let malformed = || TokenError::Malformed { name };
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(malformed());
        };

        let object = |part: &str| -> Result<Map<String, Value>, TokenError> {
            let bytes = b64_decode(part).ok_or_else(malformed)?;
            match serde_json::from_slice(&bytes) {
                Ok(Value::Object(map)) => Ok(map),
                _ => Err(malformed()),
            }
        };

        let header_map = object(header)?;
        let claims = object(payload)?;
        let signature = b64_decode(signature).ok_or_else(malformed)?;

        if header_map.get("alg").and_then(Value::as_str) != Some("RS256") {
            return Err(TokenError::UnsupportedAlgorithm { name });
        }

        Ok(Self {
            header: header_map,
            claims,
            signing_input: format!("{header}.{payload}"),
            signature,
        })
    }

    pub(crate) fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }

    pub(crate) fn typ(&self) -> Option<&str> {
        self.header.get("typ").and_then(Value::as_str)
    }

    /// Verifies the signature against an RSA public key given as big-endian `n` and `e`.
    pub(crate) fn verify(&self, n: &[u8], e: &[u8]) -> bool {
        RsaPublicKeyComponents { n, e }
            .verify(
                &RSA_PKCS1_2048_8192_SHA256,
                self.signing_input.as_bytes(),
                &self.signature,
            )
            .is_ok()
    }
}
