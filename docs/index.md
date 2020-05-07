# REST framework JWT Auth

JSON Web Token Authentication support for Django REST Framework

## Overview

This package provides [JSON Web Token Authentication][jwt-auth-spec] support for [Django REST framework][drf].

If you want to know more about JWT, check out the following resources:

- DjangoCon 2014 - JSON Web Tokens [Video][jwt-video] | [Slides][jwt-slides]
- [Auth with JSON Web Tokens][auth-jwt]
- [JWT.io][jwt-io]

## Requirements

- Python 2.7, 3.4+
- Django 1.11+
- Django REST Framework 3.7+

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

```bash
$ pip install drf-jwt
```

Add the app to your project:
```bash
INSTALLED_APPS = [
    ...
    'rest_framework_jwt',
    ...
]
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

Now in order to access protected api urls you must include the `Authorization: Bearer <your_token>` header.

```bash
$ curl -H "Authorization: Bearer <your_token>" http://localhost:8000/protected-url/
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

## Impersonation Token

Impersonation allows the service to perform actions on the client’s behalf. A typical use case would be troubleshooting. We can act like the user who submitted an issue without requiring its login credentials.

By default, only superusers (`user.is_superuser == True`) can impersonate other accounts. If you need to customize the permission handling process, override the `ImpersonateJSONWebTokenView`'s [`permission_classes` attribute](https://www.django-rest-framework.org/api-guide/permissions/#setting-the-permission-policy). 

## Blacklisting Tokens

Blacklisting allows users to blacklist their own token from the HTTP header or cookies. General
 use case is as a logout service.

### `delete_stale_tokens` management command

When called, deletes all blacklisted tokens that have expired.

## Additional Settings
There are some additional settings that you can override similar to how you'd do it with Django REST framework itself. Here are all the available defaults.

```python
JWT_AUTH = {
    'JWT_SECRET_KEY': settings.SECRET_KEY,
    'JWT_GET_USER_SECRET_KEY': None,
    'JWT_PRIVATE_KEY': None,
    'JWT_PUBLIC_KEY': None,
    'JWT_ALGORITHM': 'HS256',
    'JWT_AUDIENCE': None,
    'JWT_ISSUER': None,
    'JWT_ENCODE_HANDLER':
        'rest_framework_jwt.utils.jwt_encode_payload',
    'JWT_DECODE_HANDLER':
        'rest_framework_jwt.utils.jwt_decode_token',
    'JWT_PAYLOAD_HANDLER':
        'rest_framework_jwt.utils.jwt_create_payload',
    'JWT_PAYLOAD_GET_USERNAME_HANDLER':
        'rest_framework_jwt.utils.jwt_get_username_from_payload_handler',
    'JWT_PAYLOAD_INCLUDE_USER_ID': True,
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=300),
    'JWT_ALLOW_REFRESH': True,
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=7),
    'JWT_AUTH_HEADER_PREFIX': 'Bearer',
    'JWT_RESPONSE_PAYLOAD_HANDLER':
        'rest_framework_jwt.utils.jwt_create_response_payload',
    'JWT_AUTH_COOKIE': None,
    'JWT_AUTH_COOKIE_DOMAIN': None,
    'JWT_AUTH_COOKIE_PATH': '/',
    'JWT_AUTH_COOKIE_SECURE': True,
    'JWT_AUTH_COOKIE_SAMESITE': 'Lax',
    'JWT_IMPERSONATION_COOKIE': None,
    'JWT_DELETE_STALE_BLACKLISTED_TOKENS': False,
}
```
This package uses the JSON Web Token Python implementation, [PyJWT](https://github.com/jpadilla/pyjwt) and allows to modify some of its available options.

### JWT_SECRET_KEY

This is the secret key used to sign the JWT. Make sure this is safe and not shared or public.

Can be a dict, a list or a scalar.

* When a dict, the dict keys are taken as the JWT key ids and the values as
  keys, e.g.:

  ```python
  { "kid1": key1, "kid2": key2, ... }
  ```

  The first element is used for signing.

  If a JWT to be verified contains a key id (`kid` header), only the
  key with that id is tried (if any).

  *NOTE: For python < 3.7, use a `collections.OrderedDict` object*, e.g.:

    ```python
    from collections import OrderedDict

    JWT_AUTH["JWT_SECRET_KEY"] = OrderedDict(kid1=key1, kid2=key2, ...)
    ```

* When a list, all elements are accepted for verification and the
  first element is used for signing.

* When a scalar, this secret is used for signing and verification.

(The first) `JWT_SECRET_KEY` is only used for signing if (the first)
`JWT_ALGORITHM` is `HS*`, otherwise `JWT_PRIVATE_KEY` is used.

`JWT_SECRET_KEY`(s) is/are only used for verification of JWTs with
`alg` matching `HS*`

Default is your project's `settings.SECRET_KEY`.

### JWT_GET_USER_SECRET_KEY

This is more robust version of JWT_SECRET_KEY. It is defined per User, so in case token is compromised it can be
easily changed by owner. Changing this value will make all tokens for given user unusable. Value should be a function, accepting user as the only parameter and returning its secret key as string.

Default is `None`.

### JWT_PRIVATE_KEY

Can be a scalar or a dict.

When a dict, the dict key is taken as the JWT key id and the values as
the key, e.g.:

```python
{ "kid": key }
```

The scalar or the dict value must be in any [private key format supported by PyJWT](https://pyjwt.readthedocs.io/en/latest/algorithms.html), for example of the types

* `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
* `cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`

And will be used to sign the signature component of the JWT if `JWT_ALGORITHM` is set to any of the [supported algorithms](https://pyjwt.readthedocs.io/en/latest/algorithms.html)  other than the hash types `HS*`.

Default is `None`.

### JWT_PUBLIC_KEY

Can be a scalar, a list or a dict.

* When a dict, the dict keys are taken as the JWT key ids and the values as
  keys, e.g.:

  ```python
  { "kid1": key1, "kid2": key2, ... }
  ```

  If a JWT that contains a key id (kid header) is to be verified, only
  the associated key is tried. Otherwise, or

* when a list, all of the elements will be accepted for verification of JWTs with `alg` being (any of) `JWT_ALGORITHM` not matching `HS*`.

The scalar or elements/values of the list/dict must be in any [public key format supported by PyJWT](https://pyjwt.readthedocs.io/en/latest/algorithms.html), for example of the types

* `cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
* `cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`

Default is `None`.

### JWT_ALGORITHM

Possible values are any of the [supported algorithms](https://pyjwt.readthedocs.io/en/latest/algorithms.html) for cryptographic signing in `PyJWT`.

Can be a scalar or a list.

* For a scalar, this algorithm is used for signing and verification.

* For a list, the first element is used for signing and all elements are accepted for verification.

Default is `"HS256"`.

### JWT_INSIST_ON_KID

When key IDs are used (`JWT_SECRET_KEY` and/or `JWT_PUBLIC_KEY` given
as a dict assigning key IDs to keys), insist that JWTs to be validated
have a `kid` header with a defined key.

Default is `False`.

### JWT_AUDIENCE

This is a string that will be checked against the `aud` field of the token, if present.

Default is `None` (fail if `aud` present on JWT).

### JWT_ISSUER

This is a string that will be checked against the `iss` field of the token.

Default is `None` (do not check `iss` on JWT).

### JWT_ENCODE_HANDLER

Encodes JWT payload data and returns JWT token.

### JWT_DECODE_HANDLER

Decodes JWT token and returns JWT payload data.

### JWT_PAYLOAD_HANDLER

Specify a custom function to generate the token payload

### JWT_PAYLOAD_GET_USERNAME_HANDLER

If you store `username` differently than the default payload handler does, implement this function to fetch `username` from the payload.

### JWT_PAYLOAD_INCLUDE_USER_ID

If you do not wish to include the user's primary key (typically `id`) in the token payload, then set this to `False`.

Default is `True`.

### JWT_VERIFY

If the secret is wrong, it will raise a `jwt.DecodeError`. You can still get the payload by setting the `JWT_VERIFY` to `False`.

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

Default is `datetime.timedelta(seconds=300)` (5 minutes).

### JWT_ALLOW_REFRESH

Enable token refresh functionality. Token issued from `rest_framework_jwt.views.obtain_jwt_token` will have an `orig_iat` field.

Default is `True`.

### JWT_REFRESH_EXPIRATION_DELTA

Limit on token refresh, is a `datetime.timedelta` instance. This is how much time after the original token that future tokens can be refreshed from.

Default is `datetime.timedelta(days=7)` (7 days).

### JWT_AUTH_HEADER_PREFIX

You can modify the Authorization header value prefix that is required to be sent together with the token.

Default value is `Bearer`.

### JWT_RESPONSE_PAYLOAD_HANDLER

Creates a response payload instance that will get passed to authentication response serializer.
You might want to implement your own handler if you use custom response serializer (typical use-case would be including serialized `user` object in response).

By default returns a `namedtuple` with attributes `pk` (issued-at time) and `token`.

Example:
```
def jwt_create_response_payload(token, user=None, request=None, issued_at=None):
    """
    Return data ready to be passed to serializer.

    Override this function if you need to include any additional data for
    serializer.

    Note that we are using `pk` field here - this is for forward compatibility
    with drf add-ons that might require `pk` field in order (eg. jsonapi).
    """

    response_payload = namedtuple('ResponsePayload', 'pk token user')
    response_payload.pk = issued_at
    response_payload.token = token
    response_payload.user = user

    return response_payload
```

### JWT_AUTH_COOKIE

You can set this to a string if you want to use http cookies in addition to the Authorization header as a valid transport for the token.
The string you set here will be used as the cookie name that will be set in the response headers when requesting a token. The token validation
procedure will also look into this cookie, if set. The 'Authorization' header takes precedence if both the header and the cookie are present in the request.

Default is `None` and no cookie is set when creating tokens nor accepted when validating them.

### JWT_AUTH_COOKIE_DOMAIN

Default: `None`

The domain to use for the JWT cookie analogous to
`SESSION_COOKIE_DOMAIN` for django sessions.

Has no effect unless JWT_AUTH_COOKIE is set.

### JWT_AUTH_COOKIE_PATH

Default: `/`

The path to set on the JWT cookie analogous to `SESSION_COOKIE_PATH`
for django sessions.

Has no effect unless JWT_AUTH_COOKIE is set.

### JWT_AUTH_COOKIE_SECURE

Default: `True`

Whether to use a secure cookie for the JWT cookie analogous to
`SESSION_COOKIE_SECURE` for django sessions.

Users wishing to use JWT cookies over http (as in no TLS/SSL) need to
set `JWT_AUTH_COOKIE_SECURE` to `False.`

Has no effect unless JWT_AUTH_COOKIE is set.

### JWT_AUTH_COOKIE_SAMESITE

Default: `Lax`

The value of the `SameSite` flag on the the JWT cookie analogous to
`SESSION_COOKIE_SAMESITE` for django sessions.

Has no effect unless JWT_AUTH_COOKIE is set.

Has no effect with Django versions before 2.1.

### JWT_IMPERSONATION_COOKIE

Analogous to the `JWT_AUTH_COOKIE` setting, but contains the impersonation token, i.e. the token of the user who is being impersonated.

This cookie takes precedence over the `JWT_AUTH_COOKIE`. If you have both cookies and you want to end the impersonation, you have to remove the cookie. 

Impersonation cookies use the `JWT_AUTH_COOKIE_*` settings.

### JWT_DELETE_STALE_BLACKLISTED_TOKENS

Enables deleting of stale blacklisted tokens on `post_save` when set to `True`. All blacklisted
 tokens that have expired will be deleted.

Default is `False`.

## Extending/Overriding `JSONWebTokenAuthentication`

Right now `JSONWebTokenAuthentication` assumes that the JWT will come in the header, or a cookie if configured (see [JWT_AUTH_COOKIE](#JWT_AUTH_COOKIE)). The JWT spec does not require this (see: [Making a service Call](https://developer.atlassian.com/static/connect/docs/concepts/authentication.html)). For example, the JWT may come in the querystring. The ability to send the JWT in the querystring is needed in cases where the user cannot set the header (for example the src element in HTML).

To achieve this functionality, the user might write a custom `Authentication` class:

```python
class JSONWebTokenAuthenticationQS(JSONWebTokenAuthentication):

    def get_jwt_value(self, request):
        return request.QUERY_PARAMS.get('jwt')
```

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
