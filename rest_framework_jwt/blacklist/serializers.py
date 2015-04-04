from django.utils.translation import ugettext as _

from rest_framework import serializers

from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.serializers import VerificationBaseSerializer

from . import models

jwt_blacklist_set_handler = api_settings.JWT_BLACKLIST_SET_HANDLER


class BlacklistJSONWebTokenSerializer(VerificationBaseSerializer):
    """
    Blacklist an access token.
    """

    def validate(self, attrs):

        token = attrs['token']

        if not api_settings.JWT_ENABLE_BLACKLIST:
            msg = _('JWT_ENABLE_BLACKLIST is set to False.')
            raise serializers.ValidationError(msg)

        payload = self._check_payload(token=token)

        # Handle blacklisting a token.
        token = jwt_blacklist_set_handler(payload)

        if not token:
            msg = _('Could not blacklist token.')
            raise serializers.ValidationError(msg)

        user = self._check_user(payload=payload)

        return {
            'token': token,
            'user': user
        }


class JWTBlacklistTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.JWTBlacklistToken
