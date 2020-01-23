# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import datetime

from django import VERSION

from .settings import api_settings

try:
    from django.urls import include, url
except ImportError:
    from django.conf.urls import include, url  # noqa: F401

def has_set_cookie_samesite():
    return (VERSION >= (2,1,0))

def set_cookie_with_token(response, name, token):
    params = {
        'expires': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
        'domain': api_settings.JWT_AUTH_COOKIE_DOMAIN,
        'path': api_settings.JWT_AUTH_COOKIE_PATH,
        'secure': api_settings.JWT_AUTH_COOKIE_SECURE,
        'httponly': True
    }

    if has_set_cookie_samesite():
        params.update({'samesite': api_settings.JWT_AUTH_COOKIE_SAMESITE})

    response.set_cookie(name, token, **params)
