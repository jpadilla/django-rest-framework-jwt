from datetime import datetime

from django.db import IntegrityError
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _

from . import models


def jwt_blacklist_get_handler(payload):
    """
    Default implementation to check if a blacklisted jwt token exists.

    Should return a black listed token or None.
    """
    jti = payload.get('jti')

    try:
        token = models.JWTBlacklistToken.objects.get(jti=jti)
    except models.JWTBlacklistToken.DoesNotExist:
        return None
    else:
        return token


def jwt_blacklist_set_handler(payload):
    """
    Default implementation that blacklists a jwt token.

    Should return a black listed token or None.
    """
    try:
        data = {
            'jti': payload.get('jti'),
            'created': now(),
            'expires': datetime.fromtimestamp(payload.get('exp'))
        }
        return models.JWTBlacklistToken.objects.create(**data)
    except (TypeError, IntegrityError, Exception):
        return None


def jwt_blacklist_response_handler(token, user=None, request=None):
    """
    Default blacklist token response data. Override to provide a
    custom response.
    """
    from . import serializers
    return {
        'token': serializers.JWTBlacklistTokenSerializer(token).data,
        'message': _('Token successfully blacklisted.')
    }
