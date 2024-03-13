use jsonwebtoken::TokenData;
use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::claims;
use crate::jwk::JwkSet;
use crate::validation::ValidationOptions;

#[derive(Debug, Serialize, Deserialize)]
struct DecodedClaims {
    #[serde(flatten)]
    extra_fields: HashMap<String, claims::Claim>,
}

/// A set of JWKs that have been mapped to their key id. 
/// 
/// This is primary API for validating JWTs from an oAuth2/OIDC provider.
/// 
/// :example:
/// 
/// .. code-block:: python  
/// 
///   from base64 import urlsafe_b64encode
///   import time
///
///   import jwt # get using `pip install PyJWT``
///
///   from jwtoxide import KeyRing, ValidationOptions
///
///   encoding_key = "secret"
///   k = urlsafe_b64encode(encoding_key.encode("utf-8")).decode("utf-8")
///   jwk_set_json = f"""{{  
///   "keys": [  
///       {{
///       "kty": "oct",  
///       "alg": "HS256",  
///       "k": "{k}",
///       "kid": "key1"  
///       }}
///   ]
///   }}"""
///   data = {
///       "sub": "1234567890",
///       "exp": int(time.time()) + 60000,
///       "iat": int(time.time()),
///       "nbf": int(time.time()),
///       "name": "John Doe",
///       "aud": "test",
///       "iss": "test-issuer",
///   }
///   encoded_jwt = jwt.encode(
///       data, encoding_key, algorithm="HS256", headers={"kid": "key1"}
///   )
///   jwk_set = JwkSet.from_json(jwk_set_json)
///   key_ring = KeyRing.from_jwkset(jwk_set)
/// 
///   validation_options = ValidationOptions(
///       aud={"test"}, iss={"test-issuer"}, algorithms=["HS256"]
///   )
///   claims = key_ring.decode(encoded_jwt, validation_options=validation_options)
///
#[derive(Clone)]
#[pyclass]
pub struct KeyRing {
    pub keys: HashMap<String, jsonwebtoken::DecodingKey>,
}

#[pymethods]
impl KeyRing {
    /// Create a KeyRing from a JwkSet.
    /// 
    /// :param jwkset: The JwkSet.
    /// :type jwkset: JwkSet
    /// :return: The KeyRing.
    /// :rtype: KeyRing
    /// 
    #[classmethod]
    pub fn from_jwkset(_cls: &PyType, jwkset: &JwkSet) -> PyResult<Self> {
        let mut keys = HashMap::new();

        for k in &jwkset.jwkset.keys {
            if let Some(kid) = &k.common.key_id {
                let key = jsonwebtoken::DecodingKey::from_jwk(k).map_err(|_| {
                    PyErr::new::<exceptions::PyValueError, _>(
                        "Failed to create DecodingKey from Jwk",
                    )
                })?;
                keys.insert(kid.clone(), key);
            }
        }

        Ok(KeyRing { keys })
    }

    /// Decode a JWT token.
    /// 
    /// :param token: The JWT to decode.
    /// :type token: str
    /// :param validation_options: The options for token validation.
    /// :type validation_options: ValidationOptions
    /// :return: The decoded claims.
    /// :rtype: dict
    /// :raises: :class:`InvalidTokenError`: If the token fails validation.
    /// 
    pub fn decode(
        &self,
        token: &str,
        validation_options: &ValidationOptions,
    ) -> PyResult<HashMap<String, claims::Claim>> {
        let header = jsonwebtoken::decode_header(token).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                PyErr::new::<exceptions::PyValueError, _>("Invalid token")
            }
            _ => {
                PyErr::new::<exceptions::PyValueError, _>(format!("Failed to decode header: {}", e))
            }
        })?;
        let kid = header.kid.ok_or(PyErr::new::<exceptions::PyValueError, _>(
            "Token does not contain a key id",
        ))?;
        let decoding_key = self
            .find(&kid)
            .ok_or(PyErr::new::<exceptions::PyValueError, _>(format!(
                "Key {} not found",
                kid
            )))?;

        let token_data: TokenData<DecodedClaims> =
            jsonwebtoken::decode(token, decoding_key, &validation_options.validation).map_err(
                |e| match e.kind() {
                    jsonwebtoken::errors::ErrorKind::InvalidToken => {
                        PyErr::new::<exceptions::PyValueError, _>("Invalid token")
                    }
                    _ => PyErr::new::<exceptions::PyValueError, _>(format!(
                        "Failed to decode header: {}",
                        e
                    )),
                },
            )?;
        Ok(token_data.claims.extra_fields)
    }
}

impl KeyRing {
    pub fn find(&self, kid: &str) -> Option<&jsonwebtoken::DecodingKey> {
        self.keys.get(kid)
    }
}
