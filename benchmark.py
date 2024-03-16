import string
import random
import timeit
from jwtoxide import encode, decode, EncodingKey, DecodingKey, ValidationOptions
from jose import jwt

random.seed(5)
KEY = "asd;fkj;akljiorequsdfnzvndfjahg"


validation = ValidationOptions(
    aud=None,
    iss=None,
    verify_signature=False,
    required_spec_claims=set(),
    validate_exp=False,
    validate_nbf=False,
    validate_aud=False,
    algorithms=["HS256"],
)


def random_string(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(length))


def create_json_dicts(n):
    data_set = []
    for _ in range(n):
        data = {
            "id": random.randint(1, 100),
            "name": random_string(5),
            "age": random.randint(20, 60),
            "active": random.choice([True, False]),
            "length": random_string(15),
            "claims": {
                "roles": random_string(20),
                "sub": random_string(20),
            },
        }
        data_set.append(data)

    return data_set


json_dicts = create_json_dicts(50000)
encoded_jwts = []

encoding_key = EncodingKey.from_secret(KEY.encode("utf-8"))

for data in json_dicts:
    encoded_jwts.append(encode(data, encoding_key))


def run_itsdangerous():
    for data in json_dicts:
        jwt.encode(data, KEY)


def run_my_jwt():
    for data in json_dicts:
        encode(data, encoding_key)


decoding_key = DecodingKey.from_secret(KEY.encode("utf-8"))


def run_pyjwt_decode():
    for data in encoded_jwts:
        jwt.decode(data, KEY, algorithms=["HS256"])


def run_pyoxide_decode():
    for data in encoded_jwts:
        decode(data, decoding_key, validation_options=validation)


print(timeit.timeit(run_pyjwt_decode, number=1))
