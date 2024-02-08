from dataclasses import dataclass

import base64
import httpx
from datetime import timedelta
from typing import Any, Optional, List
from litestar import Litestar, Request, Response, get, post
from litestar.connection import ASGIConnection
from litestar.exceptions import HTTPException
from litestar.openapi.config import OpenAPIConfig
from litestar.security.jwt import OAuth2Login, OAuth2PasswordBearerAuth, Token
from pydantic import BaseModel
from okta_jwt.jwt import validate_token as validate_locally
from starlette.config import Config


@dataclass
class Credentials(BaseModel):
    client_id: str
    client_secret: str


class Item(BaseModel):
    id: int
    name: str


class OAuthSchema(BaseModel):
    """
    pretty much a copy of OAuth2Login with the 'scope' key added
    """
    token_type: str
    expires_in: int
    access_token: str
    scope: str | list[str]


API_USER_DB: dict[str, OAuthSchema] = {}

# Load environment variables
config = Config('.env')


# OAuth2PasswordBearerAuth requires a retrieve handler callable that receives the JWT token model and the ASGI
# connection and returns the 'User' instance correlating to it.
#
# Notes:
# - 'User' can be any arbitrary value you decide upon.
# - The callable can be either sync or async - both will work.
async def retrieve_user_handler(token: "Token", connection: "ASGIConnection[Any, Any, Any, Any]") \
        -> Optional[OAuthSchema]:
    """
    simple method to return the API user.
    there is only ever one API user at any point in time, which is well known to the admins so this works fine.
    :param token: jwt token of the user
    :param connection: asgi servie instance
    :return: the user
    """
    return API_USER_DB.get(token.sub)


oauth2_auth = OAuth2PasswordBearerAuth[OAuthSchema](
    retrieve_user_handler=retrieve_user_handler,
    token_secret=config('OKTA_CLIENT_SECRET'),
    # we are specifying the URL for retrieving a JWT access token
    token_url="/login",
    # we are specifying which endpoints should be excluded from authentication. In this case the login endpoint
    # and our openAPI docs.
    exclude=["/login", "/schema"],
)


def retrieve_token(authorization: str, token_url: str, scope: str) -> OAuthSchema:
    """
    retrieve the token from token url with the proper scope
    :param authorization: http auth header value
    :param token_url: endpoint which generates the token
    :param scope: security name space of the token
    :return: jwt token from token url
    """
    if scope is None:
        scope = Config('OKTA_SCOPE')
    headers = {
        'accept': 'application/json',
        'authorization': authorization,
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'client_credentials',
        'scope': scope,
    }

    response = httpx.post(token_url, headers=headers, data=data)

    if response.status_code == httpx.codes.OK:
        return OAuthSchema(**response.json())
    else:
        raise HTTPException(status_code=400, detail=response.text)


def validate_remotely(token: str, introspection: str, client_id: str, client_secret: str) -> bool:
    """
    Validate the token remotely, more secure than local validate, more time needed, more traffic
    :param token: value of the token to validate
    :param introspection: endpoint/url that is used to check the token
    :param client_id: value provided by okta setup
    :param client_secret: value provided by okta setup
    :return: true if token valid, false otherwise
    """

    headers = {
        'accept': 'application/json',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
    }
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'token': token,
    }

    response = httpx.post(introspection, headers=headers, data=data)

    return response.status_code == httpx.codes.OK and response.json()['active']


def validate_remote(token: str) -> bool:
    """
    wrapper method used to validate the token on the remote server
    :param token: value of the token to validate
    :return: true if valid
    """
    res = validate_remotely(
        token,
        config('OKTA_INTROSPECTION'),
        config('OKTA_CLIENT_ID'),
        config('OKTA_CLIENT_SECRET'),
    )

    if res:
        return True
    else:
        raise HTTPException(status_code=400)


def validate(token: str) -> bool:
    """
    Given a JWT token validate it locally.
    Quicker than remote validation, but not as secure

    :param token: token to validate
    :return: true if token is valid
    """
    try:
        res = validate_locally(
            token,
            config('OKTA_ISSUER'),
            config('OKTA_AUDIENCE'),
            config('OKTA_CLIENT_ID')
        )
        return bool(res)
    except Exception:
        raise HTTPException(status_code=403)


@get('/items')
async def read_items() -> List[Item]:
    """
    endpoint used for testing security out only
    :return: simple item list
    """
    return [
        Item(id=1, name='red ball'),
        Item(id=2, name='blue square'),
        Item(id=3, name='purple ellipse'),
    ]


# Given an instance of 'OAuth2PasswordBearerAuth' we can create a login handler function:
@post("/login")
async def login_handler(data: Credentials, request: "Request[Any, Any, Any]") -> "Response[OAuth2Login]":
    # if we do not define a response body, the login process will return a standard OAuth2 login response.
    # Note the `Response[OAuth2Login]` return type.

    # you can do whatever you want to update the response instance here
    # e.g. response.set_cookie(...)
    if data.client_id and data.client_secret:
        # create the auth header
        auth_header = 'Basic ' + str(base64.b64encode((data.client_id + ':' + data.client_secret)
                                                      .encode('ascii')))[2:-1]
    else:
        auth_header = request.headers['authorization']
    token = retrieve_token(
        auth_header,
        config('OKTA_TOKEN'),
        config('OKTA_SCOPE')
    )
    if validate_remote(token.access_token):
        # this works fine as there is only one valid user controlled by the admins
        API_USER_DB[str(token.access_token)] = token
        return oauth2_auth.login(identifier=token.access_token, token_unique_jwt_id=token.access_token,
                                 token_issuer=config('OKTA_ISSUER'), token_audience=config('OKTA_AUDIENCE'),
                                 token_expiration=timedelta(seconds=token.expires_in))


# We create our OpenAPIConfig as usual - the JWT security scheme will be injected into it.
openapi_config = OpenAPIConfig(
    title="My API",
    version="1.0.0",
)

# We initialize the app instance and pass the oauth2_auth 'on_app_init' handler to the constructor.
# The hook handler will inject the JWT middleware and openapi configuration into the app.
app = Litestar(
    route_handlers=[login_handler, read_items],
    on_app_init=[oauth2_auth.on_app_init],
    openapi_config=openapi_config,
)
