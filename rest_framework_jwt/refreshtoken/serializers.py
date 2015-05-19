from calendar import timegm
from datetime import datetime

from rest_framework import serializers
from rest_framework_jwt.compat import CurrentUserDefault
from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.serializers import (
    jwt_encode_handler,
    jwt_payload_handler,
)

from .models import RefreshToken


class RefreshTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for refresh tokens (Not RefreshJWTToken)
    """

    user = serializers.PrimaryKeyRelatedField(
        required=False,
        read_only=True,
        default=CurrentUserDefault())

    class Meta:
        model = RefreshToken
        fields = ('key', 'user', 'created', 'app')
        read_only_fields = ('key', 'created')

    def validate(self, attrs):
        """
        only for DRF < 3.0 support.
        Otherwise CurrentUserDefault() is doing the job of obtaining user
        from current request.
        """
        if 'user' not in attrs:
            attrs['user'] = self.context['request'].user
        return attrs


class DelegateJSONWebTokenSerializer(serializers.Serializer):
    def validate(self, attrs):
        user = self.context['request'].user
        payload = jwt_payload_handler(user)

        # Include original issued at time for a brand new token,
        # to allow token refresh
        if api_settings.JWT_ALLOW_REFRESH:
            payload['orig_iat'] = timegm(
                datetime.utcnow().utctimetuple()
            )

        attrs['token'] = jwt_encode_handler(payload)
        attrs['user'] = user
        return attrs
