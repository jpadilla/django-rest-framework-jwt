from calendar import timegm
from datetime import datetime

from rest_framework import serializers
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

    class Meta:
        model = RefreshToken
        fields = ('key', 'user', 'created', 'app')
        read_only_fields = ('key', 'user', 'created')

    def validate(self, attrs):
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
