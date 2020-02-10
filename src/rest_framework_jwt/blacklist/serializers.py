# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import datetime

from django.utils.timezone import make_aware

from rest_framework import serializers
from rest_framework.exceptions import APIException

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.utils import check_user, unix_epoch


class BlacklistTokenSerializer(serializers.ModelSerializer):
    """
    Serializer used for blacklisting tokens.
    """

    class Meta:
        model = BlacklistedToken
        fields = ('token', )
        extra_kwargs = {'token': {'required': False}}

    def save(self, **kwargs):
        token = self.validated_data.get('token')

        payload = JSONWebTokenAuthentication.jwt_decode_token(token)

        iat = payload.get('iat', unix_epoch())
        expires_at_unix_time = iat + api_settings.JWT_EXPIRATION_DELTA.total_seconds()

        self.validated_data.update({
            'user': check_user(payload),
            'expires_at':
                make_aware(datetime.utcfromtimestamp(expires_at_unix_time)),
        })
        return super(BlacklistTokenSerializer, self).save(**kwargs)
