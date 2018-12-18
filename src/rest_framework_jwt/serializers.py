# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import datetime

import jwt

from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import ugettext as _

from rest_framework import serializers

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.compat import PasswordField
from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.utils import unix_epoch, get_username_field


class JSONWebTokenSerializer(serializers.Serializer):
    """
    Serializer class used to validate a username and password.

    'username' is identified by the custom UserModel.USERNAME_FIELD.

    Returns a JSON Web Token that can be used to authenticate later calls.
    """

    password = PasswordField(write_only=True, required=True)
    token = serializers.CharField(read_only=True)

    def __init__(self, *args, **kwargs):
        """Dynamically add the USERNAME_FIELD to self.fields."""
        super(JSONWebTokenSerializer, self).__init__(*args, **kwargs)

        self.fields[self.username_field
                    ] = serializers.CharField(write_only=True, required=True)

    @property
    def username_field(self):
        return get_username_field()

    def validate(self, data):
        credentials = {
            self.username_field: data.get(self.username_field),
            'password': data.get('password')
        }

        if not all(credentials.values()):
            msg = _('Must include "{username_field}" and "password".')
            msg = msg.format(username_field=self.username_field)
            raise serializers.ValidationError(msg)

        user = authenticate(**credentials)

        if not user:
            msg = _('Unable to log in with provided credentials.')
            raise serializers.ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise serializers.ValidationError(msg)

        payload = JSONWebTokenAuthentication.jwt_create_payload(user)

        return {
            'token': JSONWebTokenAuthentication.jwt_encode_payload(payload),
            'user': user,
            'issued_at': payload.get('iat', unix_epoch())
        }


class BaseVerifyRefreshTokenSerializer(serializers.Serializer):
    """
    Base serializer used for verifying and refreshing JWTs.
    """

    token = serializers.CharField()

    def validate(self, data):
        msg = 'Please define a validate method.'
        raise NotImplementedError(msg)

    def _check_payload(self, token):
        try:
            payload = JSONWebTokenAuthentication.jwt_decode_token(token)
        except jwt.ExpiredSignature:
            msg = _('Token has expired.')
            raise serializers.ValidationError(msg)
        except jwt.DecodeError:
            msg = _('Error decoding token.')
            raise serializers.ValidationError(msg)

        return payload

    def _check_user(self, payload):
        username = JSONWebTokenAuthentication.\
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


class VerifyAuthTokenSerializer(BaseVerifyRefreshTokenSerializer):
    """
    Serializer used for verifying JWTs.
    """

    def validate(self, data):
        token = data['token']

        payload = self._check_payload(token=token)
        user = self._check_user(payload=payload)

        return {
            'token': token,
            'user': user,
            'issued_at': payload.get('iat', None)
        }


class RefreshAuthTokenSerializer(BaseVerifyRefreshTokenSerializer):
    """
    Serializer used for refreshing JWTs.
    """

    def validate(self, data):
        token = data['token']

        payload = self._check_payload(token=token)
        user = self._check_user(payload=payload)

        # Get and check 'orig_iat'
        orig_iat = payload.get('orig_iat')

        if not orig_iat:
            msg = _('orig_iat field not found in token.')
            raise serializers.ValidationError(msg)

        # Verify expiration
        refresh_limit = api_settings.JWT_REFRESH_EXPIRATION_DELTA

        if isinstance(refresh_limit, datetime.timedelta):
            refresh_limit = refresh_limit.total_seconds()

        expiration_timestamp = orig_iat + int(refresh_limit)
        now_timestamp = unix_epoch()

        if now_timestamp > expiration_timestamp:
            msg = _('Refresh has expired.')
            raise serializers.ValidationError(msg)

        new_payload = JSONWebTokenAuthentication.jwt_create_payload(user)
        new_payload['orig_iat'] = orig_iat

        return {
            'token':
                JSONWebTokenAuthentication.jwt_encode_payload(new_payload),
            'user':
                user,
            'issued_at':
                new_payload.get('iat', unix_epoch())
        }
