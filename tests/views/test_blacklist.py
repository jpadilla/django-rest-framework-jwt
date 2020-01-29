# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pytest

from rest_framework import status
from rest_framework.reverse import reverse

from rest_framework_jwt.blacklist.models import BlacklistedToken


def test_user_can_blacklist_own_token(user, create_authenticated_client):
    url = reverse('blacklist-list')
    data = {'user': user.id}

    api_client = create_authenticated_client(user)
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.exists()


def test_staff_user_can_blacklist_user_token(
    user, staff_user, create_authenticated_client
):
    url = reverse('blacklist-list')
    data = {'user': user.id}

    api_client_staff_user = create_authenticated_client(staff_user)
    response = api_client_staff_user.post(url, data)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.count() == 1


def test_super_user_can_blacklist_anyones_token(
    user, staff_user, super_user, create_authenticated_client
):
    url = reverse('blacklist-list')
    data = {'user': user.id}

    api_client_super_user = create_authenticated_client(super_user)
    response = api_client_super_user.post(url, data)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.count() == 1

    data = {'user': staff_user.id}
    response = api_client_super_user.post(url, data)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.count() == 2


def test_user_cannot_blacklist_someones_token(
    user, staff_user, super_user, create_authenticated_client
):
    url = reverse('blacklist-list')
    data = {'user': staff_user.id}

    api_client = create_authenticated_client(user)
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not BlacklistedToken.objects.exists()

    data = {'user': super_user.id}

    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not BlacklistedToken.objects.exists()


def test_admin_cannot_blacklist_superuser(
    staff_user, super_user, create_authenticated_client
):
    url = reverse('blacklist-list')
    data = {'user': super_user.id}

    api_client_staff_user = create_authenticated_client(staff_user)
    response = api_client_staff_user.post(url, data)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not BlacklistedToken.objects.exists()


@pytest.mark.django_db(transaction=True)
def test_blacklisted_token_cannot_be_blacklisted_again(
    user, staff_user, super_user, create_authenticated_client
):
    url = reverse('blacklist-list')
    data = {'user': user.id}

    api_client_super_user = create_authenticated_client(super_user)
    response = api_client_super_user.post(url, data)

    assert response.status_code == status.HTTP_201_CREATED
    assert BlacklistedToken.objects.count() == 1

    api_client_staff_user = create_authenticated_client(staff_user)
    response = api_client_staff_user.post(url, data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert BlacklistedToken.objects.count() == 1
