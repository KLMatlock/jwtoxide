import jwt

from jwtoxide import encode, EncodingKey, Header, Jwk


def test_create_encode_key_from_secret():
    SECRET = "secret".encode("utf-8")
    EncodingKey.from_secret(SECRET)


def test_encode_jwt():
    CLAIMS = {"foo": "bar"}
    SECRET = "secret"

    encoded_jwt = encode(CLAIMS, SECRET)
    jwt.decode(encoded_jwt, SECRET, algorithms=["HS256"])


def test_encode_jwt_header():
    header = Header(alg="HS256")
    CLAIMS = {"foo": "bar"}
    SECRET = "secret"

    encoded_jwt = encode(CLAIMS, SECRET, header=header)
    jwt.decode(encoded_jwt, SECRET, algorithms=["HS256"])
