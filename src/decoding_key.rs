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
    /// Create a key from bytes.
    ///
    /// :param content: The secret key.
    /// :type content: bytes
    /// :return: The key.
    /// :rtype: DecodingKey
    ///
    #[classmethod]
    #[pyo3(signature = (content))]
    pub fn from_secret(_cls: &PyType, content: &[u8]) -> PyResult<Self> {
        let instance = DecodingKey {
            key: jsonwebtoken::DecodingKey::from_secret(content),
        };
        Ok(instance)
    }

    /// Create a key from base64 encoded bytes.
    ///
    /// :param content: The secret key that hase been base64 encoded.
    /// :type content: str
    /// :return: The key.
    /// :rtype: DecodingKey
    ///
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

    /// Create a key from a RSA PEM file.
    ///
    /// :param content: The contents of a PEM file.
    /// :type content: str
    /// :return: The key.
    /// :rtype: DecodingKey
    ///
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

    /// Create a key from a EC PEM file.
    /// 
    /// :param content: The contents of a PEM file.
    /// :type content: str
    /// :return: The key.
    /// :rtype: DecodingKey
    /// 
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

    /// Create a key from a Ed PEM file.
    /// 
    /// :param content: The contents of a PEM file.
    /// :type content: str
    /// :return: The key.
    /// :rtype: DecodingKey
    /// 
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

    /// Create a key from a RSA DER file.
    /// 
    /// :param content: The contents of a DER file.
    /// :type content: bytes
    /// :return: The key.
    /// :rtype: DecodingKey
    /// 
    #[classmethod]
    fn from_rsa_der(_cls: &PyType, content: &[u8]) -> PyResult<Self> {
        let instance = DecodingKey {
            key: jsonwebtoken::DecodingKey::from_rsa_der(content),
        };
        Ok(instance)
    }

    /// Create a key from a EC DER file.
    /// 
    /// :param content: The contents of a DER file.
    /// :type content: bytes
    /// :return: The key.
    /// :rtype: DecodingKey
    /// 
    #[classmethod]
    fn from_ec_der(_cls: &PyType, content: &[u8]) -> PyResult<Self> {
        let instance = DecodingKey {
            key: jsonwebtoken::DecodingKey::from_ec_der(content),
        };
        Ok(instance)
    }

    /// Create a key from a Ed DER file.
    /// 
    /// :param content: The contents of a DER file.
    /// :type content: bytes
    /// :return: The key.
    /// :rtype: DecodingKey
    /// 
    #[classmethod]
    fn from_ed_der(_cls: &PyType, content: &[u8]) -> PyResult<Self> {
        let instance = DecodingKey {
            key: jsonwebtoken::DecodingKey::from_ed_der(content),
        };
        Ok(instance)
    }

    /// Create a key from a JSON Web Key (JWK).
    /// 
    /// :param jwk: The JWK.
    /// :type jwk: Jwk
    /// :return: The key.
    /// :rtype: DecodingKey
    /// 
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
