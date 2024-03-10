use pyo3::exceptions;
use pyo3::prelude::*;
use std::str::FromStr;

struct EllipticCurve(jsonwebtoken::jwk::EllipticCurve);

impl FromStr for EllipticCurve {
    type Err = PyErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "P-256" => Ok(EllipticCurve(jsonwebtoken::jwk::EllipticCurve::P256)),
            "P-384" => Ok(EllipticCurve(jsonwebtoken::jwk::EllipticCurve::P384)),
            "P-521" => Ok(EllipticCurve(jsonwebtoken::jwk::EllipticCurve::P521)),
            "Ed25519" => Ok(EllipticCurve(jsonwebtoken::jwk::EllipticCurve::Ed25519)),
            s => Err(PyErr::new::<exceptions::PyValueError, _>(format!(
                "Invalid elliptic curve: {}",
                s
            ))),
        }
    }
}

#[pyclass]
#[allow(dead_code)]
pub struct EllipticCurveKeyParameters {
    params: jsonwebtoken::jwk::EllipticCurveKeyParameters,
}

#[pymethods]
impl EllipticCurveKeyParameters {
    #[new]
    #[pyo3(signature = (curve, x, y))]
    fn new(curve: &str, x: String, y: String) -> Result<Self, PyErr> {
        let EllipticCurve(curve) = EllipticCurve::from_str(curve)?;
        Ok(EllipticCurveKeyParameters {
            params: jsonwebtoken::jwk::EllipticCurveKeyParameters {
                key_type: jsonwebtoken::jwk::EllipticCurveKeyType::default(),
                curve,
                x,
                y,
            },
        })
    }
}
