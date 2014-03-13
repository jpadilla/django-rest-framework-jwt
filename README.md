# Django REST framework JWT Auth

[![Build Status](https://travis-ci.org/GetBlimp/django-rest-framework-jwt.png?branch=master)](https://travis-ci.org/GetBlimp/django-rest-framework-jwt) [![PyPI version](https://badge.fury.io/py/djangorestframework-jwt.png)](http://badge.fury.io/py/djangorestframework-jwt)

## Overview
This package provides [JSON Web Token Authentication](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token) support for [Django REST framework](http://django-rest-framework.org/).

If you want to read more about JWT, here's a great blog post by the guys at Auth0 that talks about [Cookie vs Token based authentication](http://blog.auth0.com/2014/01/07/angularjs-authentication-with-cookies-vs-token/).

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
    	'rest_framework.authentication.SessionAuthentication',
	    'rest_framework.authentication.BasicAuthentication',
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
    ),
}
```

In your `urls.py` add the following URL route to enable obtaining a token via a POST included the user's username and password.

```python
urlpatterns = patterns(
    '',
    # ...

    url(r'^api-token-auth/', 'rest_framework_jwt.views.obtain_jwt_token'),
)
```

You can easily test if the endpoint is working by doing the following in your terminal, if you had a user created with the username **admin** and password **abc123**.

```bash
$ curl -X POST -d "username=admin&password=abc123" http://localhost:8000/api-token-auth/
```

Alternatively, you can use all the content types supported by the Django REST framework to obtain the auth token. For example:

```bash
$ curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"abc123"}' http://localhost:8000/api-token-auth/
```

Now in order to access protected api urls you must include the `Authorization: JWT <your_token>` header.

```bash
$ curl -H "Authorization: JWT <your_token>" http://localhost:8000/protected-url/
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

    'JWT_SECRET_KEY': settings.SECRET_KEY,
    'JWT_ALGORITHM': 'HS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=300)
}
```
This packages uses the JSON Web Token Python implementation, [PyJWT](https://github.com/progrium/pyjwt) and allows to modify some of it's available options.

### JWT_SECRET_KEY
This is the secret key used to encrypt the JWT. Make sure this is safe and not shared or public.

Default is your project's `settings.SECRET_KEY`.

### JWT_ALGORITHM

Possible values:

> * HS256 - HMAC using SHA-256 hash algorithm (default)
> * HS384 - HMAC using SHA-384 hash algorithm
> * HS512 - HMAC using SHA-512 hash algorithm
> * RS256 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm
> * RS384 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm
> * RS512 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm

Note:
> For the RSASSA-PKCS1-v1_5 algorithms, the "secret" argument in jwt.encode is supposed to be a private RSA key as
> imported with Crypto.PublicKey.RSA.importKey. Likewise, the "secret" argument in jwt.decode is supposed to be the
> public RSA key imported with the same method.

Default is `"HS256"`.

### JWT_VERIFY

If the secret is wrong, it will raise a jwt.DecodeError telling you as such. You can still get at the payload by setting the `JWT_VERIFY` to `False`.

Default is `True`.

### JWT_VERIFY_EXPIRATION

You can turn off expiration time verification with by setting `JWT_VERIFY_EXPIRATION` to `False`.

Default is `True`.

### JWT_LEEWAY

> This allows you to validate an expiration time which is in the past but no very far. For example, if you have a JWT payload with an expiration time set to 30 seconds after creation but you know that sometimes you will process it after 30 seconds, you can set a leeway of 10 seconds in order to have some margin.

Default is `0` seconds.


### JWT_EXPIRATION_DELTA
This is an instance of Python's `datetime.timedelta`. This will be added to `datetime.utcnow()` to set the expiration time.

Default is `datetime.timedelta(seconds=300)`(5 minutes).
