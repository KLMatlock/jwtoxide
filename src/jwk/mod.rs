use pyo3::{prelude::*, types::PyType};

pub mod algorithm;
pub mod common;


/// A JSON Web Key (JWK) that can be used to validate a JWT.
/// 
#[pyclass]
pub struct Jwk {
    pub jwk: jsonwebtoken::jwk::Jwk,
}

#[pymethods]
impl Jwk {
    /// Create a Jwk from a JSON string.
    /// 
    /// :param content: The JSON string.
    /// :type content: str
    /// :return: The JWK.
    /// :rtype: Jwk
    /// :raises: ValueError: If the JSON is invalid.
    /// 
    #[classmethod]
    pub fn from_json(_cls: &PyType, content: &str) -> PyResult<Self> {
        let deserialized: jsonwebtoken::jwk::Jwk = match serde_json::from_str(content) {
            Ok(jwk) => jwk,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid JWK: {}",
                    e
                )))
            }
        };
        Ok(Jwk { jwk: deserialized })
    }

    pub fn __str__(&self) -> String {
        format!("{:?}", self.jwk)
    }
}


/// A set of JSON Web Keys (JWKs) that can be used to validate a JWT.
/// 
#[pyclass]
pub struct JwkSet {
    pub jwkset: jsonwebtoken::jwk::JwkSet,
}

#[pymethods]
impl JwkSet {
    /// Create a JwkSet from a JSON string.
    /// 
    /// :param content: The JSON string.
    /// :type content: str
    /// :return: The JwkSet.
    /// :rtype: JwkSet
    /// :raises: ValueError: If the JSON is invalid.
    /// 
    #[classmethod]
    pub fn from_json(_cls: &PyType, content: &str) -> PyResult<Self> {
        let deserialized: jsonwebtoken::jwk::JwkSet = match serde_json::from_str(content) {
            Ok(jwk) => jwk,
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid JWK Set: {}",
                    e
                )))
            }
        };
        Ok(JwkSet {
            jwkset: deserialized,
        })
    }

    pub fn __str__(&self) -> String {
        format!("{:?}", self.jwkset)
    }
}
