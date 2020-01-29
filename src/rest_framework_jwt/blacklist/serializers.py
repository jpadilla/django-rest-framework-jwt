# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import datetime

from django.utils.timezone import make_aware

from rest_framework import serializers

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.utils import unix_epoch


class BlacklistTokenSerializer(serializers.ModelSerializer):
    """
    Serializer used for blacklisting tokens.
    """

    class Meta:
        model = BlacklistedToken
        fields = ('user', )

    def validate(self, data):
        user = data.get('user')

        payload = JSONWebTokenAuthentication.jwt_create_payload(user)
        token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        iat = payload.get('iat', unix_epoch())
        expires_at_unix_time = iat + api_settings.JWT_EXPIRATION_DELTA.total_seconds()

        return {
            'token':
                token,
            'user':
                user,
            'expires_at':
                make_aware(datetime.utcfromtimestamp(expires_at_unix_time)),
            'blacklisted_by': self.context['request'].user
        }
