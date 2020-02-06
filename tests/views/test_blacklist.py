# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import timedelta

import pytest

from django.utils import timezone

from rest_framework import status
from rest_framework.reverse import reverse

from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.settings import api_settings


@pytest.mark.django_db
def test_anonymous_user_cannot_blacklist_tokens(api_client):
    url = reverse('blacklist-list')
    response = api_client.post(url)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = api_client.post(url, {'user': 1})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_user_can_blacklist_own_token(
    user, create_authenticated_client
):
    api_client = create_authenticated_client(user)

    url = reverse('blacklist-list')
    response = api_client.post(url)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.exists()

    test_url = reverse('blacklist-test-view')

    response = api_client.get(test_url)
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_user_cannot_blacklist_same_token_multiple_times(
    user, create_authenticated_client
):
    url = reverse('blacklist-list')

    api_client = create_authenticated_client(user)
    api_client.post(url)

    assert BlacklistedToken.objects.count() == 1

    response = api_client.post(url)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert BlacklistedToken.objects.count() == 1


def test_superuser_cannot_blacklist_impersonated_user(
    monkeypatch, user, super_user, create_authenticated_client
):
    imp_cookie = "jwt-imp"
    monkeypatch.setattr(api_settings, "JWT_IMPERSONATION_COOKIE", imp_cookie)

    api_client = create_authenticated_client(super_user)

    data = {'user': user.id}
    url = reverse('impersonate')
    response = api_client.post(url, data, format='json')

    assert response.status_code == status.HTTP_200_OK

    url = reverse('blacklist-list')

    response = api_client.post(url)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.first().user_id == super_user.id


def test_user_can_blacklist_own_token_from_cookie(
    monkeypatch, user, call_auth_endpoint
):
    auth_cookie = "jwt-auth"
    monkeypatch.setattr(api_settings, "JWT_AUTH_COOKIE", auth_cookie)

    api_client = call_auth_endpoint("username", "password")

    url = reverse('blacklist-list')
    response = api_client.client.post(url)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.exists()

    test_url = reverse('blacklist-test-view')

    response = api_client.client.get(test_url)
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_stale_tokens_are_deleted_on_token_save(user, create_authenticated_client):
    blacklisted_token = BlacklistedToken.objects.create(
        token='stale_token',
        user=user,
        # Added a 300 seconds so the token doesn't seem expired and deleted on post_save
        expires_at=timezone.now() + timedelta(seconds=300),
    )
    assert BlacklistedToken.objects.exists()
    assert blacklisted_token.token == 'stale_token'

    blacklisted_token.expires_at = blacklisted_token.expires_at - timedelta(days=2)
    blacklisted_token.save()

    url = reverse('blacklist-list')
    api_client = create_authenticated_client(user)

    response = api_client.post(url)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.count() == 1
