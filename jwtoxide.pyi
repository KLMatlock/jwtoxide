from typing import Optional, Union, Literal

JsonType = Union[None, int, str, bool, list[JsonType], dict[str, JsonType]]

def encode(
    payload: dict[str, JsonType],
    key: EncodingKey | str,
    algorithm: str = "HS256",
) -> str: ...

def decode(
    token: str,
    key: EncodingKey | str,
    validation_options: ValidationOptions,
) -> dict[str, JsonType]: ...
"""
Decode a JWT using the provided keys.

Args:
    token (str): 
        The JWT to decode.

    key (EncodingKey | str): 
        The key to use for decoding. 
        This can be an EncodingKey or a string representing an utf-8 encoded secret key.

    validation_options (ValidationOptions): 
        The options for token validation.

Returns:
    dict: The decoded claims.

Raises:
    InvalidTokenError: If the token fails validation.
"""

class DecodingKey(object):
    """A key used for decoding JWTs."""

    @classmethod
    def from_secret(self, content: bytes) -> "DecodingKey": ...
    @classmethod
    def from_base64_secret(self, content: str) -> "DecodingKey": ...
    @classmethod
    def from_rsa_pem(self, content: str) -> "DecodingKey": ...
    @classmethod
    def from_ec_pem(self, content: str) -> "DecodingKey": ...
    @classmethod
    def from_ed_pem(self, content: str) -> "DecodingKey": ...
    @classmethod
    def from_rsa_der(self, content: bytes) -> "DecodingKey": ...
    @classmethod
    def from_ec_der(self, content: bytes) -> "DecodingKey": ...
    @classmethod
    def from_ed_der(self, content: bytes) -> "DecodingKey": ...
    @classmethod
    def from_jwk(self, content: Jwk) -> "DecodingKey": ...

class CommonParameters(object):
    def __init__(
        self,
        public_key_use: Optional[str] = None,
        key_operations: Optional[list[str]] = None,
        key_algorithm: Optional[str] = None,
        key_id: Optional[str] = None,
        x509_url: Optional[str] = None,
        x509_chain: Optional[list[str]] = None,
        x509_sha1_fingerprint: Optional[str] = None,
        x509_sha256_fingerprint: Optional[str] = None,
    ) -> None: ...

class EncodingKey(object):
    """A key used for encoding JWTs."""

    @classmethod
    def from_secret(self, content: bytes) -> "EncodingKey": ...
    @classmethod
    def from_base64_secret(self, content: str) -> "EncodingKey": ...
    @classmethod
    def from_rsa_pem(self, content: str) -> "EncodingKey": ...
    @classmethod
    def from_ec_pem(self, content: str) -> "EncodingKey": ...
    @classmethod
    def from_ed_pem(self, content: str) -> "EncodingKey": ...
    @classmethod
    def from_rsa_der(self, content: bytes) -> "EncodingKey": ...
    @classmethod
    def from_ec_der(self, content: bytes) -> "EncodingKey": ...
    @classmethod
    def from_ed_der(self, content: bytes) -> "EncodingKey": ...

class ValidationOptions:
    def __init__(
        self,
        aud: Optional[set[str]],
        iss: Optional[set[str]],
        sub: Optional[str] = None,
        verify_signature=True,
        required_spec_claims: set[str] = {"exp", "iat", "nbf"},
        leeway=60,
        validate_exp=True,
        validate_nbf=True,
        validate_aud=True,
        algorithms: list[str] = {
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "PS256",
            "PS384",
            "PS512",
            "EdDSA",
        },
    ) -> None: ...

class InvalidTokenError(Exception):
    """Base exception when a token fails validation."""

class DecodeError(InvalidTokenError):
    """Raised when a token cannot be decoded because it failed validation"""

class InvalidSignatureError(DecodeError):
    "Raised when a token's signature doesn't match the one provided as part of the token."

class MissingRequiredClaimError(InvalidTokenError):
    """Raised when a token is missing a required claim."""

class ExpiredSignatureError(InvalidTokenError):
    """Raised when a token's signature doesn't match the one provided as part of the token."""

class InvalidIssuerError(InvalidTokenError):
    """Raised when a token's `iss` claim does not match the expected issuer."""

class InvalidAudienceError(InvalidTokenError):
    """Raised when a token's `aud` claim does not match one of the expected audience values."""

class InvalidSubjectError(InvalidTokenError):
    """Raised when a token's `sub` claim does not match the expected subject."""

class ImmatureSignatureError(InvalidTokenError):
    """Raised when a token's `nbf` claim represents a time in the future."""

class InvalidAlgorithmError(InvalidTokenError):
    """Raised when a token's `alg` claim does not algorithm set to validate."""

class Jwk:
    @classmethod
    def from_json(cls, content: str) -> "Jwk": ...
    """
    Create a JWK from a JSON string.

    Args:  
        content (str): A JSON string representing a JWK.  

    Returns:  
        Jwk: A Jwk object.  

    Raises:  
        ValueError: If the input string is not a valid JSON or does not represent a valid JWK.  

    Example:  
        >>> jwk_json = '{"kty":"RSA","n":"0vx7...","e":"AQAB"}'  
        >>> jwk = Jwk.from_json(jwk_json)  
    """

    def __str__(self) -> str: ...

class JwkSet:
    @classmethod
    def from_json(cls, content: str) -> "JwkSet": ...
    """
    Create a JWK Set from a JSON string.

    Args:  
        content (str): A JSON string representing a JWK Set.  

    Returns:  
        JwkSet: A JwkSet object.  

    Raises:  
        ValueError: If the input string is not a valid JSON or does not represent a valid JWK Set.  

    Example:  
        >>> jwk_set_json = '{"keys":[{"kty":"RSA","n":"0vx7...","e":"AQAB"}]}'  
        >>> jwk_set = JwkSet.from_json(jwk_set_json)  
    """

    def __str__(self) -> str: ...

class KeyRing:
    @classmethod
    def from_jwkset(cls, jwk_set: JwkSet) -> "KeyRing": ...
    """
    Create a KeyRing from a JWK Set.

    Args:
        jwk_set (JwkSet): An JwkSet object.

    Returns: 
        KeyRing: A KeyRing object.

    Example:
        >>> jwk_set_json = '{"keys":[{"kty":"RSA","n":"0vx7...","e":"AQAB"}]}'
        >>> jwk_set = JwkSet.from_json(jwk_set_json)
        >>> key_ring = KeyRing.from_jwkset(jwk_set)
    """

    def decode(
        self, token: str, validation_options: ValidationOptions
    ) -> dict[str, JsonType]: ...
    """
    Decode a JWT using one of the provided keys. The keys used are found by looking for the kid in the jwt.

    Args:
        token (str): The JWT to decode.
        validation_options (ValidationOptions): The options to use when validating the token.

    Returns:
        dict: The decoded claims.
    """
