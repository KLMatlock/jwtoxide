use std::str::FromStr;

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedStr;

struct PublicKeyUse(jsonwebtoken::jwk::PublicKeyUse);

impl FromStr for PublicKeyUse {
    type Err = PyErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sig" => Ok(PublicKeyUse(jsonwebtoken::jwk::PublicKeyUse::Signature)),
            "enc" => Ok(PublicKeyUse(jsonwebtoken::jwk::PublicKeyUse::Encryption)),
            s => Ok(PublicKeyUse(jsonwebtoken::jwk::PublicKeyUse::Other(
                s.to_string(),
            ))),
        }
    }
}

struct KeyOperations(jsonwebtoken::jwk::KeyOperations);

impl FromStr for KeyOperations {
    type Err = PyErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sign" => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::Sign)),
            "verify" => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::Verify)),
            "encrypt" => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::Encrypt)),
            "decrypt" => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::Decrypt)),
            "wrapKey" => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::WrapKey)),
            "unwrapKey" => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::UnwrapKey)),
            "deriveKey" => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::DeriveKey)),
            "deriveBits" => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::DeriveBits)),
            s => Ok(KeyOperations(jsonwebtoken::jwk::KeyOperations::Other(
                s.to_string(),
            ))),
        }
    }
}

#[pyclass]
#[allow(dead_code)]
pub struct CommonParameters {
    common_parameters: jsonwebtoken::jwk::CommonParameters,
}

fn map_key_operations(
    key_operations: Vec<PyBackedStr>,
) -> Result<Vec<jsonwebtoken::jwk::KeyOperations>, PyErr> {
    key_operations
        .iter()
        .map(|s| KeyOperations::from_str(s).map(|KeyOperations(inner)| inner))
        .collect()
}

#[pymethods]
impl CommonParameters {
    #[new]
    #[pyo3(signature = (public_key_use=None, key_operations=None, key_algorithm=None, key_id=None, x509_url=None, x509_chain=None, x509_sha1_fingerprint=None, x509_sha256_fingerprint=None ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        public_key_use: Option<&str>,
        key_operations: Option<Vec<PyBackedStr>>,
        key_algorithm: Option<&str>,
        key_id: Option<String>,
        x509_url: Option<String>,
        x509_chain: Option<Vec<String>>,
        x509_sha1_fingerprint: Option<String>,
        x509_sha256_fingerprint: Option<String>,
    ) -> Result<Self, PyErr> {
        let pku = public_key_use.map(PublicKeyUse::from_str).transpose()?;
        let key_ops = key_operations.map(map_key_operations).transpose()?;
        let key_alg = match key_algorithm
            .map(jsonwebtoken::jwk::KeyAlgorithm::from_str)
            .transpose()
        {
            Ok(key_alg) => key_alg,
            Err(e) => {
                return Err(PyErr::new::<PyException, _>(format!(
                    "Could not matching for key_algorithm {}",
                    e
                )))
            }
        };
        let common_parameters = jsonwebtoken::jwk::CommonParameters {
            public_key_use: pku.map(|PublicKeyUse(inner)| inner),
            key_operations: key_ops,
            key_algorithm: key_alg,
            key_id,
            x509_url,
            x509_chain,
            x509_sha1_fingerprint,
            x509_sha256_fingerprint,
        };
        Ok(CommonParameters { common_parameters })
    }
}
