from calendar import timegm
from datetime import datetime
import warnings

import jwt

from rest_framework_jwt.compat import get_user_identifier, get_user_identifier_field
from rest_framework_jwt.settings import api_settings


jwt_user_identifier_app = api_settings.JWT_USER_IDENTIFIER_APP
jwt_user_identifier_model = api_settings.JWT_USER_IDENTIFIER_MODEL
jwt_user_identifier_field = api_settings.JWT_USER_IDENTIFIER_FIELD


def jwt_payload_handler(user):
    user_identifier_field = get_user_identifier_field()
    user_identifier = get_user_identifier(user)

    payload = {
        user_identifier_field: user_identifier,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA
    }

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
        'Use `JWT_PAYLOAD_GET_USER_IDENTIFER_HANDLER` instead.',
        DeprecationWarning
    )

    return payload.get('user_id')


def jwt_get_username_from_payload_handler(payload):
    """
    Override this function if username is formatted differently in payload
    """
    warnings.warn(
        'The following will be removed in the future. '
        'Use `JWT_PAYLOAD_GET_USER_IDENTIFIER_HANDLER` instead.',
        DeprecationWarning
    )

    return jwt_get_user_identifier_from_payload_handler(payload)


def jwt_get_user_identifier_from_payload_handler(payload):
    """
    Override this function if user identifier is formatted differently in payload
    """
    user_identifier_field = get_user_identifier_field()
    return payload.get(user_identifier_field)


def jwt_encode_handler(payload):
    return jwt.encode(
        payload,
        api_settings.JWT_SECRET_KEY,
        api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):
    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }

    return jwt.decode(
        token,
        api_settings.JWT_SECRET_KEY,
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
            'user': UserSerializer(user).data
        }

    """
    return {
        'token': token
    }
