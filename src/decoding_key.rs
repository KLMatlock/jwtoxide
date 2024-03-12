use crate::jwk::Jwk;
use pyo3::prelude::*;
use pyo3::types::PyType;

/// A key for validating a JWT signature.
///
/// Used by being passed into the `decode` function.
///
#[derive(Clone)]
#[pyclass]
pub struct DecodingKey {
    pub key: jsonwebtoken::DecodingKey,
}

#[pymethods]
impl DecodingKey {
    #[classmethod]
    pub fn from_secret(_cls: &PyType, content: &[u8]) -> PyResult<Self> {
        let instance = DecodingKey {
            key: jsonwebtoken::DecodingKey::from_secret(content),
        };
        Ok(instance)
    }

    #[classmethod]
    pub fn from_base64_secret(_cls: &PyType, content: &str) -> PyResult<Self> {
        let key = match jsonwebtoken::DecodingKey::from_base64_secret(content) {
            Ok(key) => key,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid base64 secret: {}",
                    e
                )))
            }
        };
        let instance = DecodingKey { key };
        Ok(instance)
    }

    #[classmethod]
    pub fn from_rsa_pem(_cls: &PyType, content: &str) -> PyResult<Self> {
        let key = match jsonwebtoken::DecodingKey::from_rsa_pem(content.as_bytes()) {
            Ok(key) => key,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid RSA PEM: {}",
                    e
                )))
            }
        };
        let instance = DecodingKey { key };
        Ok(instance)
    }

    #[classmethod]
    pub fn from_ec_pem(_cls: &PyType, content: &str) -> PyResult<Self> {
        let key = match jsonwebtoken::DecodingKey::from_ec_pem(content.as_bytes()) {
            Ok(key) => key,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid EC PEM: {}",
                    e
                )))
            }
        };
        let instance = DecodingKey { key };
        Ok(instance)
    }

    #[classmethod]
    fn from_ed_pem(_cls: &PyType, content: &str) -> PyResult<Self> {
        let key = match jsonwebtoken::DecodingKey::from_ed_pem(content.as_bytes()) {
            Ok(key) => key,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid Ed PEM: {}",
                    e
                )))
            }
        };
        let instance = DecodingKey { key };
        Ok(instance)
    }

    #[classmethod]
    fn from_rsa_der(_cls: &PyType, content: &[u8]) -> PyResult<Self> {
        let instance = DecodingKey {
            key: jsonwebtoken::DecodingKey::from_rsa_der(content),
        };
        Ok(instance)
    }

    #[classmethod]
    fn from_ec_der(_cls: &PyType, content: &[u8]) -> PyResult<Self> {
        let instance = DecodingKey {
            key: jsonwebtoken::DecodingKey::from_ec_der(content),
        };
        Ok(instance)
    }

    #[classmethod]
    fn from_ed_der(_cls: &PyType, content: &[u8]) -> PyResult<Self> {
        let instance = DecodingKey {
            key: jsonwebtoken::DecodingKey::from_ed_der(content),
        };
        Ok(instance)
    }

    #[classmethod]
    pub fn from_jwk(_cls: &PyType, jwk: &Jwk) -> PyResult<Self> {
        let key = match jsonwebtoken::DecodingKey::from_jwk(&jwk.jwk) {
            Ok(key) => key,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid JWK: {}",
                    e
                )))
            }
        };
        Ok(DecodingKey { key })
    }
}
