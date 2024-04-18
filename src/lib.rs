use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::{decode, DecodingKey, EncodingKey, TokenData};
use jwk::algorithm::EllipticCurveKeyParameters;
use jwk::common::CommonParameters;
use pyo3::create_exception;
use pyo3::exceptions;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

pub mod claims;
pub mod decoding_key;
pub mod encoding_key;
pub mod header;
pub mod jwk;
pub mod keyring;
pub mod validation;

create_exception!(
    _internal,
    InvalidTokenError,
    exceptions::PyException,
    "Base exception when a token fails validation."
);
create_exception!(
    _internal,
    DecodeError,
    InvalidTokenError,
    "Raised when a token cannot be decoded because it failed validation."
);
create_exception!(
    _internal,
    InvalidSignatureError,
    DecodeError,
    "Raised when a token's signature doesn't match the one provided as part of the token."
);
create_exception!(
    _internal,
    MissingRequiredClaimError,
    InvalidTokenError,
    "Raised when a claim that is required to be present is not contained in the claimset."
);
create_exception!(
    _internal,
    ExpiredSignatureError,
    InvalidTokenError,
    "Raised when a token's signature doesn't match the one provided as part of the token."
);
create_exception!(
    _internal,
    InvalidIssuerError,
    InvalidTokenError,
    "Raised when a token's `iss` claim does not match the expected issuer."
);
create_exception!(
    _internal,
    InvalidAudienceError,
    InvalidTokenError,
    "Raised when a token's `aud` claim does not match one of the expected audience values."
);
create_exception!(
    _internal,
    InvalidSubjectError,
    InvalidTokenError,
    "Raised when a token's `sub` claim does not match the expected subject."
);
create_exception!(
    _internal,
    ImmatureSignatureError,
    InvalidTokenError,
    "Raised when a token's `nbf` claim represents a time in the future."
);
create_exception!(_internal, InvalidAlgorithmError, InvalidTokenError, "Raised When the algorithm in the header doesn't match the one passed to `decode` or the encoding/decoding key used doesn't match the alg requested");

#[derive(Debug, Serialize, Deserialize)]
struct DecodedClaims {
    #[serde(flatten)]
    extra_fields: HashMap<String, claims::Claim>,
}

pub enum JsonValue {
    String(String),
}

fn encode_claims(
    claim_value: &HashMap<&str, claims::Claim>,
    key: jsonwebtoken::EncodingKey,
    algorithm: &str,
) -> Result<String, Error> {
    let algorithm = jsonwebtoken::Algorithm::from_str(algorithm)?;
    let header = jsonwebtoken::Header::new(algorithm);
    jsonwebtoken::encode(&header, &claim_value, &key)
}

fn get_encoding_key(key: &PyAny) -> Result<EncodingKey, PyErr> {
    if let Ok(py_key) = key.downcast::<pyo3::types::PyString>() {
        let key_string = py_key.to_string();
        let secret_bytes = key_string.as_bytes();
        Ok(EncodingKey::from_secret(secret_bytes))
    } else if let Ok(py_key) = key.extract::<encoding_key::EncodingKey>() {
        Ok(py_key.key)
    } else {
        Err(PyErr::new::<exceptions::PyException, _>(
            "Invalid key type, expected str or EncodingKey class.",
        ))
    }
}

fn get_decoding_key(key: &PyAny) -> Result<DecodingKey, PyErr> {
    if let Ok(py_key) = key.downcast::<pyo3::types::PyString>() {
        let key_string = py_key.to_string();
        let secret_bytes = key_string.as_bytes();
        Ok(DecodingKey::from_secret(secret_bytes))
    } else if let Ok(py_key) = key.extract::<decoding_key::DecodingKey>() {
        Ok(py_key.key)
    } else {
        Err(PyErr::new::<exceptions::PyException, _>(
            "Invalid key type, expected str or DecodingKey class.",
        ))
    }
}

/// Encode a set of claims into a Json Web Token (JWT).
///
/// :param payload: The claims to encode, must be json serializable.
/// :type payload: dict
/// :param key: The key to use for signing. This can be an EncodingKey or a string representing an utf-8 encoded secret key.
/// :type key: Union[EncodingKey, str]
/// :param algorithm: The algorithm to use for signing the token, by default uses "HS256".
/// :type algorithm: str
/// :return: The encoded token.
/// :rtype: str
/// :raises:  Exception: If an error occurs during encoding
#[pyfunction]
#[pyo3(signature = (payload, key, algorithm="HS256", header=None))]
fn encode(
    payload: HashMap<&str, claims::Claim>,
    key: &PyAny,
    algorithm: &str,
    header: Option<&PyAny>,
) -> PyResult<String> {
    if header.is_some() {
        //let header_value = header.unwrap();
        //let header_dict = header_value.extract::<Header>()?;
        return Err(PyErr::new::<exceptions::PyException, _>(
            "Header is not supported yet",
        ));
    }
    let encoding_key = get_encoding_key(key)?;
    match encode_claims(&payload, encoding_key, algorithm) {
        Ok(t) => Ok(t),
        Err(e) => Err(PyErr::new::<exceptions::PyException, _>(format!(
            "Failed to encode token: {}",
            e
        ))),
    }
}

fn parse_decode_error(error: Error) -> PyErr {
    match error.kind() {
        ErrorKind::InvalidToken => {
            PyErr::new::<InvalidTokenError, _>(format!("Token has invalid shape: {}", error))
        }
        ErrorKind::InvalidSignature => {
            PyErr::new::<InvalidSignatureError, _>("Signature validation failed")
        }
        ErrorKind::MissingRequiredClaim(claim) => {
            PyErr::new::<MissingRequiredClaimError, _>(format!("Missing required claim {}.", claim))
        }
        ErrorKind::InvalidIssuer => PyErr::new::<InvalidIssuerError, _>("Invalid issuer."),
        ErrorKind::ExpiredSignature => PyErr::new::<ExpiredSignatureError, _>("Token has expired"),
        ErrorKind::InvalidAudience => PyErr::new::<InvalidAudienceError, _>("Invalid audience."),
        ErrorKind::InvalidSubject => PyErr::new::<InvalidSubjectError, _>("Invalid subject."),
        ErrorKind::ImmatureSignature => {
            PyErr::new::<ImmatureSignatureError, _>("Token is not yet valid.")
        }
        ErrorKind::InvalidAlgorithm => PyErr::new::<InvalidAlgorithmError, _>("Invalid algorithm."),
        _ => PyErr::new::<exceptions::PyException, _>(format!("Failed to decode token: {}", error)),
    }
}

/// Decode a JWT using the provided keys.
///
/// This is a lower level api. Most users should rely on :class:`KeyRing` to decode tokens from a SSO provider.
///
/// :param token: The JWT to decode.
/// :type token: str
/// :param key: The key to use for decoding. This can be an DecodingKey or a string representing an utf-8 encoded secret key.
/// :type key: Union[DecodingKey, str]
/// :param validation_options: The options for token validation.
/// :type validation_options: ValidationOptions
/// :return: The decoded claims.
/// :rtype: dict
/// :raises: :class:`InvalidTokenError`: If the token fails validation.
///
#[pyfunction]
#[pyo3(name = "decode")]
fn py_decode(
    token: &str,
    key: &PyAny,
    validation_options: &validation::ValidationOptions,
) -> PyResult<HashMap<String, claims::Claim>> {
    let decoding_key = get_decoding_key(key)?;
    let validation = &validation_options.validation;
    let token_data: TokenData<DecodedClaims> = match decode(token, &decoding_key, validation) {
        Ok(c) => c,
        Err(e) => return Err(parse_decode_error(e)),
    };
    Ok(token_data.claims.extra_fields)
}

/// PyO3 Bindings to the jsonwebtoken library.
#[pymodule]
fn jwtoxide(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("InvalidTokenError", _py.get_type::<InvalidTokenError>())?;
    m.add("DecodeError", _py.get_type::<DecodeError>())?;
    m.add(
        "InvalidSignatureError",
        _py.get_type::<InvalidSignatureError>(),
    )?;
    m.add(
        "MissingRequiredClaimError",
        _py.get_type::<MissingRequiredClaimError>(),
    )?;
    m.add(
        "ExpiredSignatureError",
        _py.get_type::<ExpiredSignatureError>(),
    )?;
    m.add("InvalidIssuerError", _py.get_type::<InvalidIssuerError>())?;
    m.add(
        "InvalidAudienceError",
        _py.get_type::<InvalidAudienceError>(),
    )?;
    m.add("InvalidSubjectError", _py.get_type::<InvalidSubjectError>())?;
    m.add(
        "ImmatureSignatureError",
        _py.get_type::<ImmatureSignatureError>(),
    )?;
    m.add(
        "InvalidAlgorithmError",
        _py.get_type::<InvalidAlgorithmError>(),
    )?;
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    m.add_function(wrap_pyfunction!(py_decode, m)?)?;
    m.add_class::<CommonParameters>()?;
    m.add_class::<EllipticCurveKeyParameters>()?;
    m.add_class::<encoding_key::EncodingKey>()?;
    m.add_class::<decoding_key::DecodingKey>()?;
    m.add_class::<validation::ValidationOptions>()?;
    m.add_class::<jwk::Jwk>()?;
    m.add_class::<jwk::JwkSet>()?;
    m.add_class::<keyring::KeyRing>()?;
    Ok(())
}
