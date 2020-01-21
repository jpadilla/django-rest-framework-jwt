
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import jwt

from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _

from rest_framework import serializers

from rest_framework_jwt.authentication import JSONWebTokenAuthentication


def _check_payload(token):
    try:
        payload = JSONWebTokenAuthentication.jwt_decode_token(token)
    except jwt.ExpiredSignature:
        msg = _('Token has expired.')
        raise serializers.ValidationError(msg)
    except jwt.DecodeError:
        msg = _('Error decoding token.')
        raise serializers.ValidationError(msg)

    return payload


def _check_user(payload):
    username = JSONWebTokenAuthentication. \
        jwt_get_username_from_payload(payload)

    if not username:
        msg = _('Invalid token.')
        raise serializers.ValidationError(msg)

    # Make sure user exists
    try:
        User = get_user_model()
        user = User.objects.get_by_natural_key(username)
    except User.DoesNotExist:
        msg = _("User doesn't exist.")
        raise serializers.ValidationError(msg)

    if not user.is_active:
        msg = _('User account is disabled.')
        raise serializers.ValidationError(msg)

    return user


class BlacklistTokenSerializer(serializers.Serializer):
    """
    Serializer used for blacklisting tokens.
    """

    token = serializers.CharField(required=False)
