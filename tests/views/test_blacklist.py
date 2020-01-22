# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from rest_framework import status
from rest_framework.reverse import reverse

from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.serializers import JSONWebTokenAuthentication


def test_only_user_can_blacklist_own_token(
    user, staff_user, create_authenticated_client
):
    assert not BlacklistedToken.objects.exists()

    api_client_staff_user = create_authenticated_client(staff_user)
    payload = JSONWebTokenAuthentication.jwt_create_payload(user)

    url = reverse('blacklist-list')
    data = {'token': JSONWebTokenAuthentication.jwt_encode_payload(payload)}

    # Response should return status 403 Forbidden if anyone besides the
    # owner tries to blacklist a token
    response = api_client_staff_user.post(url, data)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not BlacklistedToken.objects.exists()

    # Owner can blacklist own token
    api_client = create_authenticated_client(user)
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_200_OK
    assert BlacklistedToken.objects.exists()
