<div class="badges">
    <a href="https://travis-ci.org/jpadilla/django-rest-framework-jwt">
        <img src="https://travis-ci.org/jpadilla/django-rest-framework-jwt.svg?branch=master">
    </a>
    <a href="https://pypi.python.org/pypi/djangorestframework-jwt">
        <img src="https://img.shields.io/pypi/v/djangorestframework-jwt.svg">
    </a>
</div>

---

# REST framework JWT Auth

JSON Web Token Authentication support for Django REST Framework

---

## Overview

This package provides [JSON Web Token Authentication][jwt-auth-spec] support for [Django REST framework][drf].

If you want to know more about JWT, check out the following resources:

- DjangoCon 2014 - JSON Web Tokens [Video][jwt-video] | [Slides][jwt-slides]
- [Auth with JSON Web Tokens][auth-jwt]
- [JWT.io][jwt-io]

## Requirements

- Python (2.7, 3.3, 3.4, 3.5, 3.6)
- Django (1.8, 1.9, 1.10)
- Django REST Framework (3.0, 3.1, 3.2, 3.3, 3.4, 3.5)

## Security

Unlike some more typical uses of JWTs, this module only generates
authentication tokens that will verify the user who is requesting one of your DRF
protected API resources. The actual
request parameters themselves are *not* included in the JWT claims which means
they are not signed and may be tampered with. You should only expose your API
endpoints over SSL/TLS to protect against content tampering and certain kinds of
replay attacks.

## Installation

Install using `pip`...

```
$ pip install djangorestframework-jwt
```

## Usage

In your `settings.py`, add `JSONWebTokenAuthentication` to Django REST framework's `DEFAULT_AUTHENTICATION_CLASSES`.

```python
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
}
```

In your `urls.py` add the following URL route to enable obtaining a token via a POST included the user's username and password.

```python
from rest_framework_jwt.views import obtain_jwt_token
#...

urlpatterns = [
    '',
    # ...

    url(r'^api-token-auth/', obtain_jwt_token),
]
```

You can easily test if the endpoint is working by doing the following in your terminal, if you had a user created with the username **admin** and password **password123**.

```bash
$ curl -X POST -d "username=admin&password=password123" http://localhost:8000/api-token-auth/
```

Alternatively, you can use all the content types supported by the Django REST framework to obtain the auth token. For example:

```bash
$ curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"password123"}' http://localhost:8000/api-token-auth/
```

Now in order to access protected api urls you must include the `Authorization: JWT <your_token>` header.

```bash
$ curl -H "Authorization: JWT <your_token>" http://localhost:8000/protected-url/
```

## Refresh Token
If `JWT_ALLOW_REFRESH` is True, **non-expired** tokens can be "refreshed" to obtain a brand new token with renewed expiration time. Add a URL pattern like this:
```python
    from rest_framework_jwt.views import refresh_jwt_token
    #  ...

    urlpatterns = [
        #  ...
        url(r'^api-token-refresh/', refresh_jwt_token),
    ]
```

Pass in an existing token to the refresh endpoint as follows: `{"token": EXISTING_TOKEN}`. Note that only non-expired tokens will work. The JSON response looks the same as the normal obtain token endpoint `{"token": NEW_TOKEN}`.

```bash
$ curl -X POST -H "Content-Type: application/json" -d '{"token":"<EXISTING_TOKEN>"}' http://localhost:8000/api-token-refresh/
```

Refresh with tokens can be repeated (token1 -> token2 -> token3), but this chain of token stores the time that the original token (obtained with username/password credentials), as `orig_iat`. You can only keep refreshing tokens up to `JWT_REFRESH_EXPIRATION_DELTA`.

A typical use case might be a web app where you'd like to keep the user "logged in" the site without having to re-enter their password, or get kicked out by surprise before their token expired. Imagine they had a 1-hour token and are just at the last minute while they're still doing something. With mobile you could perhaps store the username/password to get a new token, but this is not a great idea in a browser. Each time the user loads the page, you can check if there is an existing non-expired token and if it's close to being expired, refresh it to extend their session. In other words, if a user is actively using your site, they can keep their "session" alive.

## Verify Token

In some microservice architectures, authentication is handled by a single service. Other services delegate the responsibility of confirming that a user is logged in to this authentication service. This usually means that a service will pass a JWT received from the user to the authentication service, and wait for a confirmation that the JWT is valid before returning protected resources to the user.

This setup is supported in this package using a verification endpoint. Add the following URL pattern:
```python
    from rest_framework_jwt.views import verify_jwt_token

    #...

    urlpatterns = [
        #  ...
        url(r'^api-token-verify/', verify_jwt_token),
    ]
```

Passing a token to the verification endpoint will return a 200 response and the token if it is valid. Otherwise, it will return a 400 Bad Request as well as an error identifying why the token was invalid.

```bash
$ curl -X POST -H "Content-Type: application/json" -d '{"token":"<EXISTING_TOKEN>"}' http://localhost:8000/api-token-verify/
```

## Additional Settings
There are some additional settings that you can override similar to how you'd do it with Django REST framework itself. Here are all the available defaults.

```python
JWT_AUTH = {
    'JWT_ENCODE_HANDLER':
    'rest_framework_jwt.utils.jwt_encode_handler',

    'JWT_DECODE_HANDLER':
    'rest_framework_jwt.utils.jwt_decode_handler',

    'JWT_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_payload_handler',

    'JWT_PAYLOAD_GET_USER_ID_HANDLER':
    'rest_framework_jwt.utils.jwt_get_user_id_from_payload_handler',

    'JWT_RESPONSE_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_response_payload_handler',

    'JWT_SECRET_KEY': settings.SECRET_KEY,
    'JWT_GET_USER_SECRET_KEY': None,
    'JWT_PUBLIC_KEY': None,
    'JWT_PRIVATE_KEY': None,
    'JWT_ALGORITHM': 'HS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=300),
    'JWT_AUDIENCE': None,
    'JWT_ISSUER': None,

    'JWT_ALLOW_REFRESH': False,
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=7),

    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'JWT_AUTH_COOKIE': None,

}
```
This packages uses the JSON Web Token Python implementation, [PyJWT](https://github.com/jpadilla/pyjwt) and allows to modify some of it's available options.

### JWT_SECRET_KEY
This is the secret key used to sign the JWT. Make sure this is safe and not shared or public.

Default is your project's `settings.SECRET_KEY`.

### JWT_GET_USER_SECRET_KEY
This is more robust version of JWT_SECRET_KEY. It is defined per User, so in case token is compromised it can be
easily changed by owner. Changing this value will make all tokens for given user unusable. Value should be a function, accepting user as only parameter and returning it's secret key.

Default is `None`.

### JWT_PUBLIC_KEY
This is an object of type `cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`. It will be used to verify the signature of the incoming JWT. Will override `JWT_SECRET_KEY` when set. Read the [documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey) for more details. Please note that `JWT_ALGORITHM` must be set to one of `RS256`, `RS384`, or `RS512`.

Default is `None`.

### JWT_PRIVATE_KEY
This is an object of type `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`. It will be used to sign the signature component of the JWT. Will override `JWT_SECRET_KEY` when set. Read the [documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey) for more details. Please note that `JWT_ALGORITHM` must be set to one of `RS256`, `RS384`, or `RS512`.

Default is `None`.

### JWT_ALGORITHM

Possible values are any of the [supported algorithms](https://github.com/jpadilla/pyjwt#algorithms) for cryptographic signing in PyJWT.

Default is `"HS256"`.

### JWT_VERIFY

If the secret is wrong, it will raise a jwt.DecodeError telling you as such. You can still get at the payload by setting the `JWT_VERIFY` to `False`.

Default is `True`.

### JWT_VERIFY_EXPIRATION

You can turn off expiration time verification by setting `JWT_VERIFY_EXPIRATION` to `False`.
Without expiration verification, JWTs will last forever meaning a leaked token could be used by an attacker indefinitely.

Default is `True`.

### JWT_LEEWAY

This allows you to validate an expiration time which is in the past but not very far. For example, if you have a JWT payload with an expiration time set to 30 seconds after creation but you know that sometimes you will process it after 30 seconds, you can set a leeway of 10 seconds in order to have some margin.

Default is `0` seconds.

### JWT_EXPIRATION_DELTA
This is an instance of Python's `datetime.timedelta`. This will be added to `datetime.utcnow()` to set the expiration time.

Default is `datetime.timedelta(seconds=300)`(5 minutes).

### JWT_AUDIENCE
This is a string that will be checked against the `aud` field of the token, if present.

Default is `None`(fail if `aud` present on JWT).

### JWT_ISSUER
This is a string that will be checked against the `iss` field of the token.

Default is `None`(do not check `iss` on JWT).

### JWT_ALLOW_REFRESH
Enable token refresh functionality. Token issued from `rest_framework_jwt.views.obtain_jwt_token` will have an `orig_iat` field. Default is `False`

### JWT_REFRESH_EXPIRATION_DELTA
Limit on token refresh, is a `datetime.timedelta` instance. This is how much time after the original token that future tokens can be refreshed from.

Default is `datetime.timedelta(days=7)` (7 days).

### JWT_PAYLOAD_HANDLER
Specify a custom function to generate the token payload

### JWT_PAYLOAD_GET_USER_ID_HANDLER
If you store `user_id` differently than the default payload handler does, implement this function to fetch `user_id` from the payload. **Note:** Will be deprecated in favor of `JWT_PAYLOAD_GET_USERNAME_HANDLER`.

### JWT_PAYLOAD_GET_USERNAME_HANDLER
If you store `username` differently than the default payload handler does, implement this function to fetch `username` from the payload.

### JWT_RESPONSE_PAYLOAD_HANDLER
Responsible for controlling the response data returned after login or refresh. Override to return a custom response such as including the serialized representation of the User.

Defaults to return the JWT token.

Example:
```
def jwt_response_payload_handler(token, user=None, request=None):
    return {
        'token': token,
        'user': UserSerializer(user, context={'request': request}).data
    }
```

Default is `{'token': token}`

### JWT_AUTH_HEADER_PREFIX
You can modify the Authorization header value prefix that is required to be sent together with the token. The default value is `JWT`. This decision was introduced in PR [#4](https://github.com/jpadilla/django-rest-framework-jwt/pull/4) to allow using both this package and OAuth2 in DRF.

Another common value used for tokens and Authorization headers is `Bearer`.

Default is `JWT`.

### JWT_AUTH_COOKIE
You can set this to a string if you want to use http cookies in addition to the Authorization header as a valid transport for the token.
The string you set here will be used as the cookie name that will be set in the response headers when requesting a token. The token validation
procedure will also look into this cookie, if set. The 'Authorization' header takes precedence if both the header and the cookie are present in the request.

Default is `None` and no cookie is set when creating tokens nor accepted when validating them.

## Extending `JSONWebTokenAuthentication`

Right now `JSONWebTokenAuthentication` assumes that the JWT will come in the header, or a cookie if configured (see [JWT_AUTH_COOKIE](#JWT_AUTH_COOKIE)). The JWT spec does not require this (see: [Making a service Call](https://developer.atlassian.com/static/connect/docs/concepts/authentication.html)). For example, the JWT may come in the querystring. The ability to send the JWT in the querystring is needed in cases where the user cannot set the header (for example the src element in HTML).

To achieve this functionality, the user might write a custom `Authentication`:
```python
class JSONWebTokenAuthenticationQS(BaseJSONWebTokenAuthentication):
    def get_jwt_value(self, request):
         return request.QUERY_PARAMS.get('jwt')
```
It is recommended to use `BaseJSONWebTokenAuthentication`, a new base class with no logic around parsing the HTTP headers.

## Creating a new token manually ##

Sometimes you may want to manually generate a token, for example to return a token to the user immediately after account creation. You can do this as follows:

```python
from rest_framework_jwt.settings import api_settings

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

payload = jwt_payload_handler(user)
token = jwt_encode_handler(payload)
```

[jwt-auth-spec]: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
[drf]: http://django-rest-framework.org/
[jwt-video]: https://www.youtube.com/watch?v=825hodQ61bg
[jwt-slides]: https://speakerdeck.com/jpadilla/djangocon-json-web-tokens
[auth-jwt]: http://jpadilla.com/post/73791304724/auth-with-json-web-tokens
[jwt-io]: http://jwt.io/
