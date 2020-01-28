# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from rest_framework import serializers

from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.utils import check_payload, check_user, unix_epoch


class BlacklistTokenSerializer(serializers.Serializer):
    """
    Serializer used for blacklisting tokens.
    """

    token = serializers.CharField(required=False)
