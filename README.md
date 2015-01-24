# REST framework JWT Auth

[![build-status-image]][travis]
[![pypi-version]][pypi]

**JSON Web Token Authentication support for Django REST Framework**

Full documentation for the project is available at [docs][docs].

## Overview

This package provides [JSON Web Token Authentication][jwt-auth-spec] support for [Django REST framework][drf].

If you want to know more about JWT, check out the following resources:

- DjangoCon 2014 - JSON Web Tokens [Video][jwt-video] | [Slides][jwt-slides]
- [Auth with JSON Web Tokens][auth-jwt]
- [JWT.io][jwt-io]

## Requirements

- Python (2.7, 3.2, 3.3, 3.4)
- Django (1.6, 1.7)
- Django REST Framework (2.4.3, 2.4.4, 3.0.0)

## Installation

Install using `pip`...

```bash
$ pip install djangorestframework-jwt
```

## Documentation & Support

Full documentation for the project is available at [docs][docs].

You may also want to follow the [author][blimp] on Twitter.

[build-status-image]: https://secure.travis-ci.org/GetBlimp/django-rest-framework-jwt.png?branch=master
[travis]: http://travis-ci.org/GetBlimp/django-rest-framework-jwt?branch=master
[pypi-version]: https://pypip.in/version/djangorestframework-jwt/badge.svg
[pypi]: https://pypi.python.org/pypi/djangorestframework-jwt
[jwt-auth-spec]: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
[drf]: http://django-rest-framework.org/
[jwt-video]: https://www.youtube.com/watch?v=825hodQ61bg
[jwt-slides]: https://speakerdeck.com/jpadilla/djangocon-json-web-tokens
[auth-jwt]: http://jpadilla.com/post/73791304724/auth-with-json-web-tokens
[jwt-io]: http://jwt.io/
[docs]: http://getblimp.github.io/django-rest-framework-jwt
[blimp]: https://twitter.com/blimp
