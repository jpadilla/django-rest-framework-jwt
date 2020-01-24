# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.utils.translation import ugettext_lazy as _

from rest_framework import status
from rest_framework.reverse import reverse

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings


def test_superuser_can_impersonate(
        user, super_user, create_authenticated_client
):

    api_client = create_authenticated_client(super_user)

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    token = response.json()["token"]
    payload = JSONWebTokenAuthentication.jwt_decode_token(token)

    assert response.status_code == status.HTTP_200_OK
    assert "token" in response.json()
    assert payload["user_id"] == user.id


def test_staff_user_cannot_impersonate(
        user, staff_user, create_authenticated_client
):

    api_client = create_authenticated_client(staff_user)

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_normal_user_cannot_impersonate(user, create_authenticated_client):

    api_client = create_authenticated_client(user)

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_anonymous_user_cannot_impersonate(api_client):

    url = reverse("impersonate")
    response = api_client.post(url, format="json")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_superuser_cannot_impersonate_inactive_user(
    user, super_user, create_authenticated_client
):

    api_client = create_authenticated_client(super_user)

    user.is_active = False
    user.save()

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    expected_output = {"non_field_errors": [_("User account is disabled.")]}

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == expected_output


def test_impersonation_sets_cookie(
    monkeypatch, user, super_user, create_authenticated_client
):

    imp_cookie = "jwt-imp"
    monkeypatch.setattr(api_settings, "JWT_IMPERSONATION_COOKIE", imp_cookie)

    api_client = create_authenticated_client(super_user)

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    token = response.json()["token"]
    payload = JSONWebTokenAuthentication.jwt_decode_token(token)

    cookie_token = response.client.cookies.get(imp_cookie)
    cookie_payload = JSONWebTokenAuthentication.jwt_decode_token(cookie_token.value)

    assert response.status_code == status.HTTP_200_OK
    assert "token" in response.json()
    assert imp_cookie in response.client.cookies
    assert payload["user_id"] == user.id
    assert cookie_payload["user_id"] == user.id


def test_view_with_impersonation_cookie(
    monkeypatch, user, super_user, call_auth_endpoint
):

    auth_cookie = "jwt-auth"
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE", auth_cookie)

    imp_cookie = "jwt-imp"
    monkeypatch.setattr(api_settings, "JWT_IMPERSONATION_COOKIE", imp_cookie)

    api_client = call_auth_endpoint("superusername", "super")

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.client.post(url, data, format="json")

    url = reverse("superuser-test-view")
    response = response.client.get(url)

    assert response.status_code == status.HTTP_403_FORBIDDEN

    url = reverse("test-view")
    response = response.client.get(url)

    assert response.status_code == status.HTTP_200_OK
