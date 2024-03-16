import time

import pytest

import jwt
from jwtoxide import (
    decode,
    ValidationOptions,
    InvalidSignatureError,
    MissingRequiredClaimError,
    ExpiredSignatureError,
    InvalidIssuerError,
    InvalidAudienceError,
    InvalidSubjectError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
)


def test_valid_decode():
    """Basic test to ensure that a valid token is decoded correctly."""
    data = {
        "sub": "1234567890",
        "exp": int(time.time()) + 60000,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "name": "John Doe",
        "aud": "test",
        "iss": "test-issuer",
    }
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        aud={"test"}, iss={"test-issuer"}, algorithms=["HS256"]
    )
    decoded_claims = decode(
        encoded_jwt, "secret", validation_options=validation_options
    )
    assert all(data[claim] == decoded_claims[claim] for claim in data)


def test_decode_no_claim_validation():
    """Test that the token is decoded correctly when no claim validation is required."""
    data = {"sub": "1234567890", "name": "John Doe", "admin": True}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        aud=None,
        iss=None,
        required_spec_claims=set(),
        validate_exp=False,
        validate_nbf=False,
        validate_aud=False,
        algorithms=["HS256"],
    )

    decoded_claims = decode(
        encoded_jwt, "secret", validation_options=validation_options
    )
    assert all(data[claim] == decoded_claims[claim] for claim in data)


def test_decode_invalid_signature():
    """Test that error raised when the signature is invalid."""
    data = {"sub": "1234567890", "name": "John Doe", "admin": True}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(aud=None, iss=None, algorithms=["HS256"])

    with pytest.raises(InvalidSignatureError):
        decode(encoded_jwt, "foo", validation_options=validation_options)


def test_decode_invalid_signature_no_validation():
    """Test that the token is decoded correctly when signature validation is not required."""
    data = {"sub": "1234567890", "name": "John Doe", "admin": True}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        aud=None,
        iss=None,
        verify_signature=False,
        required_spec_claims=set(),
        validate_exp=False,
        validate_nbf=False,
        validate_aud=False,
        algorithms=["HS256"],
    )

    decoded_claims = decode(encoded_jwt, "foo", validation_options=validation_options)
    assert all(data[claim] == decoded_claims[claim] for claim in data)


def test_missing_required_claim():
    """Test that error raised when a required claim is missing."""
    data = {"sub": "1234567890", "name": "John Doe", "admin": True}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        aud=None,
        iss=None,
        validate_exp=False,
        validate_nbf=False,
        validate_aud=False,
        algorithms=["HS256"],
    )

    with pytest.raises(MissingRequiredClaimError):
        decode(encoded_jwt, "secret", validation_options=validation_options)


def test_expired_signature():
    """Test that error raised when the token has expired."""
    data = {
        "sub": "1234567890",
        "exp": int(time.time()) - 1000,
        "iat": int(time.time()) - 5000,
        "nbf": int(time.time()) - 5000,
        "name": "John Doe",
    }
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(aud=None, iss=None, algorithms=["HS256"])

    with pytest.raises(ExpiredSignatureError):
        decode(encoded_jwt, "secret", validation_options=validation_options)


def test_invalid_exp():
    """Test that error raised when the exp claim is an invalid type."""
    data = {
        "sub": "1234567890",
        "exp": str(int(time.time()) - 1000),
        "iat": int(time.time()) - 5000,
        "nbf": int(time.time()) - 5000,
        "name": "John Doe",
    }
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(aud=None, iss=None, algorithms=["HS256"])

    with pytest.raises(MissingRequiredClaimError):
        decode(encoded_jwt, "secret", validation_options=validation_options)


def test_expired_leeway():
    """Test that the leeway is taken into account when validating the token."""
    data = {
        "sub": "1234567890",
        "exp": int(time.time()) - 50,
        "iat": int(time.time()) - 120,
        "nbf": int(time.time()) - 120,
        "name": "John Doe",
    }
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(aud=None, iss=None, leeway_seconds = 60, algorithms=["HS256"])

    decode(encoded_jwt, "secret", validation_options=validation_options)


def test_invalid_issuer():
    """Test that error raised when the issuer is invalid."""
    data = {"iss": "foo"}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        aud=None,
        iss={"bar"},
        verify_signature=False,
        required_spec_claims=set(),
        algorithms=["HS256"],
    )

    with pytest.raises(InvalidIssuerError):
        decode(encoded_jwt, "secret", validation_options=validation_options)


def test_valid_issuer():
    """Test correct decode when the issuer is valid."""
    data = {"iss": "foo"}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        aud=None,
        iss={"foo", "bar"},
        verify_signature=False,
        required_spec_claims={"iss"},
        algorithms=["HS256"],
    )

    decode(encoded_jwt, "secret", validation_options=validation_options)


def test_invalid_audience():
    """Test that error raised when the audience is invalid."""
    data = {"aud": "foo"}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        iss=None,
        verify_signature=False,
        required_spec_claims={"aud"},
        aud={"bar"},
        algorithms=["HS256"],
    )

    with pytest.raises(InvalidAudienceError):
        decode(encoded_jwt, "secret", validation_options=validation_options)


def test_valid_audience():
    """Test correct decode when the audience is valid."""
    data = {"aud": "foo"}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        iss=None,
        verify_signature=False,
        required_spec_claims={"aud"},
        aud={"bar", "foo"},
        algorithms=["HS256"],
    )

    decode(encoded_jwt, "secret", validation_options=validation_options)


def test_invalid_subject():
    """Test that error raised when the subject is invalid."""
    data = {"sub": "foo"}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        iss=None,
        aud=None,
        verify_signature=False,
        required_spec_claims={"sub"},
        sub="bar",
        algorithms=["HS256"],
    )

    with pytest.raises(InvalidSubjectError):
        decode(encoded_jwt, "secret", validation_options=validation_options)


def test_valid_sub():
    """Test correct decode when the sub is valid."""
    data = {"sub": "foo"}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(
        aud=None,
        iss=None,
        verify_signature=False,
        required_spec_claims={"sub"},
        sub="foo",
        algorithms=["HS256"],
    )

    decode(encoded_jwt, "secret", validation_options=validation_options)


def test_immature_signature():
    """Test that error raised when the token is not yet valid."""
    data = {
        "sub": "1234567890",
        "exp": int(time.time()) + 1000,
        "iat": int(time.time()) + 1000,
        "nbf": int(time.time()) + 1000,
        "name": "John Doe",
    }
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS256")
    validation_options = ValidationOptions(aud=None, iss=None, algorithms=["HS256"])

    with pytest.raises(ImmatureSignatureError):
        decode(encoded_jwt, "secret", validation_options=validation_options)


def test_invalid_algorithm():
    """Test that error raised when the algorithm is invalid."""
    data = {"sub": "1234567890"}
    encoded_jwt = jwt.encode(data, "secret", algorithm="HS512")
    validation_options = ValidationOptions(aud=None, iss=None, algorithms=["HS256"])

    with pytest.raises(InvalidAlgorithmError):
        decode(encoded_jwt, "secret", validation_options=validation_options)
