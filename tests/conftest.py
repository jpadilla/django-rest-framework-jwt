# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pytest

from django.contrib.auth import get_user_model

from rest_framework.test import APIClient

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings


User = get_user_model()


@pytest.fixture
def create_authenticated_client(api_client):
    def _create_authenticated_client(user):
        payload = JSONWebTokenAuthentication.jwt_create_payload(user)
        token = JSONWebTokenAuthentication.jwt_encode_payload(payload)
        api_client.credentials(
            HTTP_AUTHORIZATION="{prefix} {token}".format(
                prefix=api_settings.JWT_AUTH_HEADER_PREFIX, token=token
            )
        )
        return api_client

    yield _create_authenticated_client

    # Clear the authorization header
    api_client.credentials()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def user(create_user):
    return create_user(
        username="username",
        email="username@example.com",
        password="password",
        is_active=True,
        is_staff=False,
        is_superuser=False,
    )


@pytest.fixture
def staff_user(create_user):
    return create_user(
        username="staffusername",
        email="staffusername@example.com",
        password="staff",
        is_active=True,
        is_staff=True,
        is_superuser=False,
    )


@pytest.fixture
def super_user(create_user):
    return create_user(
        username="superusername",
        email="superusername@example.com",
        password="super",
        is_active=True,
        is_staff=True,
        is_superuser=True,
    )


@pytest.fixture
def create_user(db):
    def _create_user(**kwargs):
        return User.objects.create_user(**kwargs)

    return _create_user
