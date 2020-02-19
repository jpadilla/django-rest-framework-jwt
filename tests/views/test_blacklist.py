# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import timedelta

from django.core.management import call_command

from django.utils import timezone

from rest_framework import status
from rest_framework.reverse import reverse

from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.settings import api_settings


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


def test_stale_tokens_are_deleted_on_token_save_when_feature_is_activated(
    monkeypatch, user, staff_user, create_authenticated_client
):
    blacklisted_token = BlacklistedToken.objects.create(
        token='stale_token',
        user=user,
        expires_at=timezone.now(),
    )
    assert BlacklistedToken.objects.exists()
    assert blacklisted_token.token == 'stale_token'

    blacklisted_token.expires_at = blacklisted_token.expires_at - timedelta(days=2)
    blacklisted_token.save()

    url = reverse('blacklist-list')
    api_client = create_authenticated_client(user)

    response = api_client.post(url)

    assert response.status_code == status.HTTP_201_CREATED
    # No token is deleted because the feature is not turned on
    assert BlacklistedToken.objects.count() == 2

    monkeypatch.setattr(api_settings, 'JWT_DELETE_STALE_BLACKLISTED_TOKENS', True)

    api_client = create_authenticated_client(staff_user)

    response = api_client.post(url)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.count() == 2


def test_delete_stale_tokens_by_calling_the_management_command(
    user, create_authenticated_client
):
    for num in range(1, 6):
        BlacklistedToken.objects.create(
            token='stale_token_{}'.format(num),
            user=user,
            expires_at=timezone.now() - timedelta(days=num),
        )
    assert BlacklistedToken.objects.count() == 5

    BlacklistedToken.objects.create(
        token='valid_token',
        user=user,
        expires_at=timezone.now() + timedelta(days=1),
    )
    assert BlacklistedToken.objects.count() == 6

    call_command('delete_stale_tokens')
    assert BlacklistedToken.objects.count() == 1
