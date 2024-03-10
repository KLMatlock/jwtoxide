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

#[derive(Clone)]
#[pyclass]
pub struct KeyRing {
    pub keys: HashMap<String, jsonwebtoken::DecodingKey>,
}

#[pymethods]
impl KeyRing {
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
