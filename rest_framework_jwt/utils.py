import jwt
import uuid
import warnings
from calendar import timegm
from datetime import datetime

from rest_framework_jwt.compat import get_username, get_username_field
from rest_framework_jwt.settings import api_settings


def jwt_payload_handler(user):
    username_field = get_username_field()
    username = get_username(user)

    warnings.warn(
        'The following fields will be removed in the future: '
        '`email` and `user_id`. ',
        DeprecationWarning
    )

    payload = {
        'user_id': user.pk,
        'email': user.email,
        'username': username,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA
    }

    try:
        from bson import objectid
    except ImportError:
        if isinstance(user.pk, uuid.UUID):
            payload['user_id'] = str(user.pk)
    else:
        if isinstance(user.pk, (uuid.UUID, objectid.ObjectId)):
            payload['user_id'] = str(user.pk)

    payload[username_field] = username

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    warnings.warn(
        'The following will be removed in the future. '
        'Use `JWT_PAYLOAD_GET_USERNAME_HANDLER` instead.',
        DeprecationWarning
    )

    return payload.get('user_id')


def jwt_get_username_from_payload_handler(payload):
    """
    Override this function if username is formatted differently in payload
    """
    return payload.get('username')


def jwt_encode_handler(payload):
    return jwt.encode(
        payload,
        api_settings.JWT_PRIVATE_KEY or api_settings.JWT_SECRET_KEY,
        api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):
    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }

    return jwt.decode(
        token,
        api_settings.JWT_PUBLIC_KEY or api_settings.JWT_SECRET_KEY,
        api_settings.JWT_VERIFY,
        options=options,
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
            'user': UserSerializer(user, context={'request': request}).data
        }

    """
    return {
        'token': token
    }
