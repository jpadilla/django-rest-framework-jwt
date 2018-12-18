# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json

from rest_framework.reverse import reverse


def call_auth_endpoint(api_client, username, password):
    """Call /auth endpoint with given username and password."""
    credentials = {"username": username, "password": password}

    url = reverse('auth')
    return api_client.post(
        path=url, data=json.dumps(credentials), content_type='application/json'
    )


def call_auth_verify_endpoint(api_client, token):
    """Call /auth/verify endpoint with given token."""
    url = reverse('auth-verify')
    return api_client.post(
        path=url, data=json.dumps({
            "token": token
        }), content_type='application/json'
    )


def call_auth_refresh_endpoint(api_client, token):
    """Call /auth/refresh endpoint with given token."""
    url = reverse('auth-refresh')
    return api_client.post(
        path=url, data=json.dumps({
            "token": token
        }), content_type='application/json'
    )
