import jwt
import uuid

from django.db import IntegrityError
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _

from datetime import datetime

from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.blacklist import models
from rest_framework_jwt.blacklist import serializers


def get_user_model():
    try:
        from django.contrib.auth import get_user_model
    except ImportError:  # Django < 1.5
        from django.contrib.auth.models import User
    else:
        User = get_user_model()

    return User


def jwt_payload_handler(user):
    try:
        username = user.get_username()
    except AttributeError:
        username = user.username

    return {
        'user_id': user.pk,
        'email': user.email,
        'username': username,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
        'jti': uuid.uuid4().hex
    }


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    return payload.get('user_id')


def jwt_encode_handler(payload):
    return jwt.encode(
        payload,
        api_settings.JWT_SECRET_KEY,
        api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):
    return jwt.decode(
        token,
        api_settings.JWT_SECRET_KEY,
        api_settings.JWT_VERIFY,
        verify_expiration=api_settings.JWT_VERIFY_EXPIRATION,
        leeway=api_settings.JWT_LEEWAY,
        audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER,
        algorithms=[api_settings.JWT_ALGORITHM]
    )


def jwt_response_payload_handler(token, user=None, request=None):
    """
    Returns the response data for both the login and refresh views.
    Override to return a custom response such as including the
    serialized representation of the User.

    Example:

    def jwt_response_payload_handler(token, user=None, request=None):
        return {
            'token': token,
            'user': UserSerializer(user).data
        }

    """

    return {
        'token': token
    }


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
    return {
        'token': serializers.JWTBlacklistTokenSerializer(token).data,
        'message': _('Token successfully blacklisted.')
    }
