=======
Example 
=======
  
This is an example of JWT Authentication for FastAPI using Keycloak as an OIDC provider.  
  
Prerequisites  
=============  
- Docker and Docker Compose installed on your machine.  
- FastAPI, httpx and jwtoxide installed in your Python environment.  
  
Getting Started  
===============  
Here are the steps to run this project:  
  
1. Start a Keycloak server using the provided docker-compose file. You can do this by running the command `docker-compose up` in the directory containing the docker-compose file.  
  
2. Once the Keycloak server has started, log in to the Keycloak admin console at http://localhost:8080. Use the following credentials:  
   - Username: `admin`  
   - Password: `admin`  
  
3. After logging in, create a new confidential client in Keycloak. Name this client "fastapi".   
  
4. Set the "Valid Redirect URIs" for this new client to "http://localhost:8000/\*".  
  
Securing a FastAPI Endpoint with Keycloak Authentication
========================================================

In order to authenticate with Keycloak, you will need to retrieve the oAuth2.0 information Keycloak's "well-known" endpoint.

This information can be found at the following URL: http://localhost:8080/auth/realms/master/.well-known/openid-configuration.

From this response we can retrieve url for the JWKs from the `jwks_uri` endpoint.
Here's how you can retrieve the JWKS using `httpx`:

.. code-block:: python 

    import httpx

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


We can now secure our FastAPI endpoints. This is done by creating a dependency that validates the access token provided through the `Auth` header.

If the token is valid, the function will return the token's claims. If not, it will raise an HTTPException with a 401 status code.

.. code-block:: python 

    from fastapi import FastAPI, HTTPException, Depends, status
    from fastapi.security import OpenIdConnect

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
        import uvicorn
        uvicorn.run(app)

This will also be represented in the Swagger (`/docs`) url of FastAPI. 

When accessed, you will see a new `Authorize` button that will allow you to authenticate with Keycloak and retrieve the access token.