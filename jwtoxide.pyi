from typing import Optional, Union

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


class DecodingKey(object):

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
        leeway_seconds=60,
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
    ...

class DecodeError(InvalidTokenError):
    ...

class InvalidSignatureError(DecodeError):
    ...

class MissingRequiredClaimError(InvalidTokenError):
    ...

class ExpiredSignatureError(InvalidTokenError):
    ...

class InvalidIssuerError(InvalidTokenError):
    ...

class InvalidAudienceError(InvalidTokenError):
    ...

class InvalidSubjectError(InvalidTokenError):
    ...

class ImmatureSignatureError(InvalidTokenError):
    ...

class InvalidAlgorithmError(InvalidTokenError):
    ...

class Jwk:
    @classmethod
    def from_json(cls, content: str) -> "Jwk": ...

    def __str__(self) -> str: ...

class JwkSet:
    @classmethod
    def from_json(cls, content: str) -> "JwkSet": ...

    def __str__(self) -> str: ...

class KeyRing:
    @classmethod
    def from_jwkset(cls, jwk_set: JwkSet) -> "KeyRing": ...

    def decode(
        self, token: str, validation_options: ValidationOptions
    ) -> dict[str, JsonType]: ...
