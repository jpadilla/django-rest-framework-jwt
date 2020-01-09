# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework_jwt.settings import api_settings


def test_superuser_can_impersonate(user, super_user, create_authenticated_client):

    api_client = create_authenticated_client(super_user)

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert "token" in response.json()


def test_staff_user_can_impersonate(user, staff_user, create_authenticated_client):

    api_client = create_authenticated_client(staff_user)

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    assert response.status_code == status.HTTP_200_OK
    assert "token" in response.json()


def test_normal_user_cannot_impersonate(user, create_authenticated_client):

    api_client = create_authenticated_client(user)

    data = {"user": user.id}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_anonymous_user_cannot_impersonate(api_client):

    url = reverse("impersonate")
    response = api_client.post(url, format='json')

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_serializer_not_valid_superuser(super_user, create_authenticated_client):

    api_client = create_authenticated_client(super_user)

    data = {"user": 0}
    url = reverse("impersonate")
    response = api_client.post(url, data, format="json")

    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_user_return_token_and_cookie(monkeypatch, api_client):

    url = reverse("impersonate")
    response = api_client.post(url, format="json")

    imp_cookie = "jwt-imp"
    monkeypatch.setattr(api_settings, "JWT_IMPERSONATION_COOKIE", imp_cookie)

    assert imp_cookie in response.cookies
