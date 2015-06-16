from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_jwt.compat import CurrentUserDefault, Serializer

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


class DelegateJSONWebTokenSerializer(Serializer):
    client_id = serializers.CharField()
    grant_type = serializers.CharField(
        default='urn:ietf:params:oauth:grant-type:jwt-bearer',
        required=False,
    )
    refresh_token = serializers.CharField()
    api_type = serializers.CharField(
        default='app',
        required=False,
    )

    def validate(self, attrs):
        refresh_token = attrs['refresh_token']
        try:
            token = RefreshToken.objects.select_related('user').get(
                key=refresh_token)
        except RefreshToken.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))
        attrs['user'] = token.user
        return attrs
