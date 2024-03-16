from base64 import urlsafe_b64encode
import time

import pytest

import jwt

from jwtoxide import Jwk, JwkSet, KeyRing, ValidationOptions


def test_jwk_from_json():
    jwk_json = '{"kty":"RSA","n":"0vx7...","e":"AQAB"}'
    Jwk.from_json(jwk_json)


def test_jwk_invalid():
    jwk_json = '"kty":"RSA","n":"0vx7...","e":"AQAB"'
    with pytest.raises(ValueError):
        Jwk.from_json(jwk_json)


def test_jwk_set_from_json():
    jwk_set_json = '{"keys":[{"kty":"RSA","n":"0vx7...","e":"AQAB"}]}'
    JwkSet.from_json(jwk_set_json)


def test_keyring_from_jwk_set():
    encoding_key = "secret"
    k = urlsafe_b64encode(encoding_key.encode("utf-8")).decode("utf-8")
    jwk_set_json = f"""{{  
    "keys": [  
        {{
        "kty": "oct",  
        "alg": "HS256",  
        "k": "{k}",
        "kid": "key1"  
        }}
    ]
    }}"""
    data = {
        "sub": "1234567890",
        "exp": int(time.time()) + 60000,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "name": "John Doe",
        "aud": "test",
        "iss": "test-issuer",
    }
    encoded_jwt = jwt.encode(
        data, encoding_key, algorithm="HS256", headers={"kid": "key1"}
    )
    jwk_set = JwkSet.from_json(jwk_set_json)
    key_ring = KeyRing.from_jwkset(jwk_set)

    validation_options = ValidationOptions(
        aud={"test"}, iss={"test-issuer"}, algorithms=["HS256"]
    )
    key_ring.decode(encoded_jwt, validation_options=validation_options)
