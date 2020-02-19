# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pytest

from rest_framework import status
from rest_framework.reverse import reverse

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.compat import gettext_lazy as _
from rest_framework_jwt.settings import api_settings


def test_view_requires_authentication(api_client):
    url = reverse("test-view")
    response = api_client.get(url)

    expected_output = {
        "detail": _("Authentication credentials were not provided.")
    }

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


def test_view_returns_200_to_authenticated_user(
    create_authenticated_client, user
):
    api_client = create_authenticated_client(user)

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_view_returns_401_for_invalid_token(api_client):
    token = "invalid"
    api_client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

    expected_output = {"detail": _("Error decoding token.")}

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


def test_view_returns_401_for_expired_token(api_client, user):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["iat"] = 0
    payload["exp"] = 1
    token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    api_client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

    expected_output = {"detail": _("Token has expired.")}

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


def test_view_returns_401_to_deactivated_user(api_client, user):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    token = JSONWebTokenAuthentication.jwt_encode_payload(payload)
    user.is_active = False
    user.save()

    api_client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

    expected_output = {"detail": _("User account is disabled.")}

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


def test_view_returns_401_when_username_does_not_exist(api_client, user):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload["username"] = "i_do_not_exist"
    token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    api_client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

    expected_output = {"detail": _("Invalid token.")}

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


def test_view_returns_401_when_token_does_not_contain_username(
    api_client, user
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    payload.pop("username")
    token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    api_client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

    expected_output = {"detail": _("Invalid payload.")}

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


@pytest.mark.django_db
def test_view_returns_401_to_authorization_header_without_token(api_client):
    api_client.credentials(HTTP_AUTHORIZATION="Bearer ")

    expected_output = {
        "detail": _("Authentication credentials were not provided.")
    }

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


def test_view_returns_401_to_authorization_header_token_with_spaces(
    api_client, user
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    token = JSONWebTokenAuthentication.jwt_encode_payload(payload)
    token = token.replace(".", " ")

    api_client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

    expected_output = {
        "detail": _(
            "Authentication credentials were not provided."
        )
    }

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


def test_view_returns_401_to_invalid_token_prefix(api_client, user):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)
    token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

    api_client.credentials(HTTP_AUTHORIZATION="INVALID_PREFIX " + token)

    expected_output = {
        "detail": _("Authentication credentials were not provided.")
    }

    url = reverse("test-view")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == expected_output


def test_view__auth_cookie(monkeypatch, user, call_auth_endpoint):
    auth_cookie = "jwt-auth"
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE", auth_cookie)

    response = call_auth_endpoint("username", "password")

    url = reverse("test-view")
    response = response.client.get(url)

    assert response.status_code == status.HTTP_200_OK
