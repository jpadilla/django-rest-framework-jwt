# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from rest_framework import status
from rest_framework.reverse import reverse

from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.serializers import JSONWebTokenAuthentication


def test_user_can_blacklist_own_token(user, create_authenticated_client):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)

    url = reverse('blacklist-list')
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}

    api_client = create_authenticated_client(user)
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_200_OK
    assert BlacklistedToken.objects.exists()


def test_staff_user_can_blacklist_user_token(
    user, staff_user, create_authenticated_client
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)

    url = reverse('blacklist-list')
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}

    api_client_staff_user = create_authenticated_client(staff_user)
    response = api_client_staff_user.post(url, data)

    assert response.status_code == status.HTTP_200_OK
    assert BlacklistedToken.objects.count() == 1


def test_super_user_can_blacklist_anyones_token(
    user, staff_user, super_user, create_authenticated_client
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)

    url = reverse('blacklist-list')
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}

    api_client_super_user = create_authenticated_client(super_user)
    response = api_client_super_user.post(url, data)

    assert response.status_code == status.HTTP_200_OK
    assert BlacklistedToken.objects.count() == 1

    payload = JSONWebTokenAuthentication.jwt_create_payload(staff_user)
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}
    response = api_client_super_user.post(url, data)

    assert response.status_code == status.HTTP_200_OK
    assert BlacklistedToken.objects.count() == 2


def test_user_cannot_blacklist_someones_token(
    user, staff_user, super_user, create_authenticated_client
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(staff_user)
    url = reverse('blacklist-list')
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}

    api_client = create_authenticated_client(user)
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not BlacklistedToken.objects.exists()

    payload = JSONWebTokenAuthentication.jwt_create_payload(super_user)
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}

    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not BlacklistedToken.objects.exists()


def test_admin_cannot_blacklist_superuser(
    staff_user, super_user, create_authenticated_client
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(super_user)
    url = reverse('blacklist-list')
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}

    api_client_staff_user = create_authenticated_client(staff_user)
    response = api_client_staff_user.post(url, data)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not BlacklistedToken.objects.exists()


def test_blacklisted_token_cannot_be_blacklisted_again(
    user, staff_user, super_user, create_authenticated_client
):
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)

    url = reverse('blacklist-list')
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}

    api_client_super_user = create_authenticated_client(super_user)
    response = api_client_super_user.post(url, data)

    assert response.status_code == status.HTTP_200_OK
    assert BlacklistedToken.objects.count() == 1

    api_client_staff_user = create_authenticated_client(staff_user)
    response = api_client_staff_user.post(url, data)

    assert response.status_code == status.HTTP_200_OK
    assert BlacklistedToken.objects.count() == 1
