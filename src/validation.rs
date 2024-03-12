use jsonwebtoken::Algorithm;
use pyo3::prelude::*;
use std::collections::HashSet;
use std::str::FromStr;

const DEFAULT_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Sets the validation options when decoding a JWT
///
/// :param aud: Optional; The required audience claim, if set to None then no checking
///     is performed.
/// :type aud: set[str], optional
/// :param iss: Optional; The required issuer, typically the URL of an oauth provider,
///     if set to None then no checking is performed.
/// :type iss: set[str], optional
/// :param sub: Optional; The required subject claim, if set to None then no checking
///     is performed. Defaults to None.
/// :type sub: str, optional
/// :param required_spec_claims: The claims that are required to be present in the JWT.
///     Note only checks for presences of the claim, does not validate the value.
///     Defaults to {"exp", "iat", "nbf"}.
/// :type required_spec_claims: set[str], optional
/// :param leeway_seconds: The leeway for validating time based claims in second.
///     Defaults to 60 seconds.
/// :type leeway_seconds: int, optional
/// :param validate_exp: Whether to validate the expiration time claim, defaults to True.
/// :type validate_exp: bool, optional
/// :param validate_nbf: Whether to validate the not-before time claim, defaults to True.
/// :type validate_nbf: bool, optional
/// :param validate_aud: Whether to validate the audience claim, defaults to True.
/// :type validate_aud: bool, optional
/// :param algorithms: The algorithms that can be used, defaults to
///     {"RS256","RS384","RS512","ES256","ES384","PS256","PS384","PS512","EdDSA"}.
/// :type algorithms: list[str], optional
/// :param verify_signature: Whether to verify the signature, very dangerous to turn
///     this off. Defaults to True.
/// :type verify_signature: bool, optional
#[pyclass]
pub struct ValidationOptions {
    pub validation: jsonwebtoken::Validation,
}

#[pymethods]
impl ValidationOptions {
    #[new]
    #[pyo3(signature = (
        aud,
        iss,
        sub = None,
        required_spec_claims = None,
        leeway_seconds = 5,
        validate_exp = true,
        validate_nbf = true,
        validate_aud = true,
        algorithms = None,
        verify_signature = true,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        aud: Option<HashSet<String>>,
        iss: Option<HashSet<String>>,
        sub: Option<String>,
        required_spec_claims: Option<HashSet<String>>,
        leeway_seconds: u64,
        validate_exp: bool,
        validate_nbf: bool,
        validate_aud: bool,
        algorithms: Option<Vec<&str>>,
        verify_signature: bool,
    ) -> Self {
        let mut validation = jsonwebtoken::Validation::new(Algorithm::EdDSA);
        let algorithm_vec = match algorithms {
            Some(algos) => algos
                .iter()
                .map(|s| Algorithm::from_str(s).unwrap())
                .collect(),
            None => DEFAULT_ALGORITHMS.to_vec(),
        };
        validation.algorithms = algorithm_vec;
        let req_spec_claims: HashSet<String> = match required_spec_claims {
            Some(claims) => claims,
            None => {
                let mut claims = HashSet::new();
                claims.insert("exp".to_string());
                claims.insert("iat".to_string());
                claims.insert("nbf".to_string());
                claims
            }
        };
        validation.required_spec_claims = req_spec_claims;
        validation.leeway = leeway_seconds;
        validation.validate_exp = validate_exp;
        validation.validate_nbf = validate_nbf;
        validation.validate_aud = validate_aud;
        validation.iss = iss;
        validation.aud = aud;
        validation.sub = sub;
        if !verify_signature {
            validation.insecure_disable_signature_validation();
        }

        ValidationOptions { validation }
    }

    fn __str__(&self) -> String {
        format!("{:?}", self.validation)
    }
}
