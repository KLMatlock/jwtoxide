"""Example JWT Authentication for FastAPI using Keycloak as an OIDC provider.

To run, first start a Keycloak server using the provided docker-compose file.
Once started, log in to the Keycloak admin console at http://localhost:8080
using the username `admin` and password `admin`. Then, create a new confidential
client called "fastapi" and set the "Valid Redirect URIs" to "http://localhost:8000/*".

Afterwards, install both FastAPI and httpx using pip. Then start this script,
go to localhost:8000/docs to see the authenticated endpoints.
"""

from typing import Annotated

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OpenIdConnect
import httpx
import uvicorn

from jwtoxide import JwkSet, KeyRing, ValidationOptions, InvalidTokenError

KEYCLOAK_URL = "http://localhost:8080/realms/master"
WELL_KNOWN_URL = f"{KEYCLOAK_URL}/.well-known/openid-configuration"

oauth2_scheme = OpenIdConnect(openIdConnectUrl=WELL_KNOWN_URL)

well_known_config = httpx.get(WELL_KNOWN_URL).json()
jwks_url = well_known_config["jwks_uri"]
jwks_response = httpx.get(jwks_url)

jwkset = JwkSet.from_json(jwks_response.text)
key_ring = KeyRing.from_jwkset(jwkset)
validation_options = ValidationOptions(
    required_spec_claims={"iat", "exp"},
    aud={"master-realm"},
    iss={KEYCLOAK_URL},
    algorithms=["RS256"],
)

app = FastAPI()


async def get_claims(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    jwt_token = token[7:]
    try:
        return key_ring.decode(jwt_token, validation_options=validation_options)
    except InvalidTokenError:
        raise credentials_exception


@app.get("/secured")
async def secured(claims: dict = Depends(get_claims)):
    return {"claims": claims}


if __name__ == "__main__":
    uvicorn.run(app)
