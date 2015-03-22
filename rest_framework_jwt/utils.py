import random
import string
from datetime import datetime

import jwt
from django.utils.translation import gettext_lazy as _

from rest_framework_jwt.settings import api_settings

if api_settings.JWT_ENABLE_BLACKLIST:
    import pymongo
    jti_collection = pymongo.MongoClient().jwt_db.jti_collection


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

    payload = {
        'user_id': user.pk,
        'email': user.email,
        'username': username,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA
    }

    if 'jti' not in payload:
        payload['jti'] = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(20))

    return payload


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    user_id = payload.get('user_id')
    return user_id


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

    def jwt_response_payload_handler(token, user=None):
        return {
            'token': token,
            'user': UserSerializer(user).data
        }

    """

    return {
        'token': token
    }


def jwt_is_blacklisted(payload):
    if 'jti' not in payload or api_settings.JWT_ENABLE_BLACKLIST is False:
        return False

    return jti_collection.find_one({'jti': payload['jti']}) is not None


def jwt_blacklist(payload):
    if 'jti' not in payload:
        raise ValueError(_("Can't blacklist payloads that don't have a jti claim"))

    if not jwt_is_blacklisted(payload):
        jti_collection.insert({'jti': payload['jti'],
                               'payload': payload})
