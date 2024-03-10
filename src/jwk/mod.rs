use pyo3::{prelude::*, types::PyType};

pub mod algorithm;
pub mod common;

#[pyclass]
pub struct Jwk {
    pub jwk: jsonwebtoken::jwk::Jwk,
}

#[pymethods]
impl Jwk {
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

#[pyclass]
pub struct JwkSet {
    pub jwkset: jsonwebtoken::jwk::JwkSet,
}

#[pymethods]
impl JwkSet {
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
