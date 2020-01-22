
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from rest_framework import serializers


class BlacklistTokenSerializer(serializers.Serializer):
    """
    Serializer used for blacklisting tokens.
    """

    token = serializers.CharField(required=False)
