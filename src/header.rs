use crate::jwk::Jwk;
use pyo3::prelude::*;
use std::str::FromStr;

/// A basic JWT header, the alg defaults to HS256 and typ is automatically set to JWT. All the other fields are optional.
///
/// :param alg: Optional; The algorithm used, defined in `RFC7515#4.1.1 <https://tools.ietf.org/html/rfc7515#section-4.1.1>`_.
/// :type alg: str, optional
/// :param kid: Optional; Key ID, a hint indicating which key was used to secure the JWT.
///     Defined in `RFC7515#4.1.4 <https://tools.ietf.org/html/rfc7515#section-4.1.4>`_.
/// :type kid: str, optional
/// :param typ: Optional; The type of the token, by default this will be "JWT".
/// :type typ: str, optional
/// :param cty: Optional; The content type of the token, defined in `RFC7519#5.2 <https://tools.ietf.org/html/rfc7519#section-5.2>`_.
/// :type cty: str, optional
/// :param jku: Optional; The URL of the JWK Set, defined in `RFC7515#4.1.2 <https://tools.ietf.org/html/rfc7515#section-4.1.2>`_.
/// :type jku: str, optional
/// :param jwk: Optional; The JSON Web Key, defined in `RFC7515#4.1.3 <https://tools.ietf.org/html/rfc7515#section-4.1.3>`_.
/// :type jwk: Jwk, optional
/// :param x5u: Optional; The URL of the X.509 certificate or certificate chain, defined in `RFC7515#4.1.5 <https://tools.ietf.org/html/rfc7515#section-4.1.5>`_.
/// :type x5u: str, optional
/// :param x5c: Optional; The X.509 certificate or certificate chain, defined in `RFC7515#4.1.6 <https://tools.ietf.org/html/rfc7515#section-4.1.6>`_.
/// :type x5c: list[str], optional
/// :param x5t: Optional; The X.509 certificate SHA-1 thumbprint, defined in `RFC7515#4.1.7 <https://tools.ietf.org/html/rfc7515#section-4.1.7>`_.
/// :type x5t: str, optional
/// :param x5t_s256: Optional; The X.509 certificate SHA-256 thumbprint, defined in `RFC7515#4.1.8 <https://tools.ietf.org/html/rfc7515#section-4.1.8>`_.
/// :type x5t_s256: str, optional
#[pyclass]
pub struct Header {
    pub rs_header: jsonwebtoken::Header,
}

#[pymethods]
impl Header {
    #[new]
    #[pyo3(signature = (alg = None, kid = None, typ = None, cty = None, jku = None, jwk = None, x5u = None, x5c = None, x5t = None, x5t_s256 = None))]
    fn new(
        alg: Option<&str>,
        kid: Option<String>,
        typ: Option<String>,
        cty: Option<String>,
        jku: Option<String>,
        jwk: Option<&Jwk>,
        x5u: Option<String>,
        x5c: Option<Vec<String>>,
        x5t: Option<String>,
        x5t_s256: Option<String>,
    ) -> Self {
        let alg = match alg {
            Some(alg) => jsonwebtoken::Algorithm::from_str(alg).unwrap(),
            None => jsonwebtoken::Algorithm::default(),
        };
        let mut rs_header = jsonwebtoken::Header::new(alg);
        if let Some(kid) = kid {
            rs_header.kid = Some(kid);
        }
        if let Some(typ) = typ {
            rs_header.typ = Some(typ);
        }
        if let Some(cty) = cty {
            rs_header.cty = Some(cty);
        }
        if let Some(jku) = jku {
            rs_header.jku = Some(jku);
        }
        if let Some(jwk) = jwk {
            rs_header.jwk = Some(jwk.jwk.clone());
        }
        if let Some(x5u) = x5u {
            rs_header.x5u = Some(x5u);
        }
        if let Some(x5c) = x5c {
            rs_header.x5c = Some(x5c);
        }
        if let Some(x5t) = x5t {
            rs_header.x5t = Some(x5t);
        }
        if let Some(x5t_s256) = x5t_s256 {
            rs_header.x5t_s256 = Some(x5t_s256);
        }
        Header { rs_header }
    }

    fn __str__(&self) -> String {
        format!("{:?}", self.rs_header)
    }
}
