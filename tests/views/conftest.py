# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pytest

from rest_framework.reverse import reverse


@pytest.fixture
def call_auth_endpoint(api_client, db):
    def _call_auth_endpoint(username, password):
        url = reverse("auth")
        data = {"username": username, "password": password}
        return api_client.post(path=url, data=data)

    return _call_auth_endpoint


@pytest.fixture
def call_auth_verify_endpoint(api_client, db):
    def _call_auth_verify_endpoint(token):
        url = reverse("auth-verify")
        data = {"token": token}
        return api_client.post(path=url, data=data)

    return _call_auth_verify_endpoint


@pytest.fixture
def call_auth_refresh_endpoint(api_client, db):
    def _call_auth_refresh_endpoint(token):
        url = reverse("auth-refresh")
        data = {"token": token}
        return api_client.post(path=url, data=data)

    return _call_auth_refresh_endpoint
