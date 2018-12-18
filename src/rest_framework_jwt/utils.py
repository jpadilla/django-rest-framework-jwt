# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from calendar import timegm
from collections import namedtuple
from datetime import datetime

import jwt

from django.contrib.auth import get_user_model
from django.utils.encoding import force_text

from rest_framework_jwt.settings import api_settings


def unix_epoch(datetime_object=None):
    """Get unix epoch from datetime object."""

    if not datetime_object:
        datetime_object = datetime.utcnow()
    return timegm(datetime_object.utctimetuple())


def get_username_field():
    try:
        username_field = get_user_model().USERNAME_FIELD
    except AttributeError:
        username_field = 'username'

    return username_field


def get_username(user):
    try:
        username = user.get_username()
    except AttributeError:
        username = user.username

    return username


def jwt_get_secret_key(payload=None):
    """
    For enhanced security you may want to use a secret key based on user.

    This way you have an option to logout only this user if:
        - token is compromised
        - password is changed
        - etc.
    """
    if api_settings.JWT_GET_USER_SECRET_KEY:
        User = get_user_model()  # noqa: N806
        user = User.objects.get(pk=payload.get('user_id'))
        key = str(api_settings.JWT_GET_USER_SECRET_KEY(user))
        return key
    return api_settings.JWT_SECRET_KEY


def jwt_create_payload(user):
    """
    Create JWT claims token.

    To be more standards-compliant please refer to the official JWT standards
    specification: https://tools.ietf.org/html/rfc7519#section-4.1
    """

    username = get_username(user)

    issued_at_time = datetime.utcnow()
    expiration_time = issued_at_time + api_settings.JWT_EXPIRATION_DELTA

    payload = {
        'user_id': user.pk,
        'username': username,
        'iat': unix_epoch(issued_at_time),
        'exp': expiration_time
    }

    # It's common practice to have user object attached to profile objects.
    # If you have some other implementation feel free to create your own
    # `jwt_create_payload` method with custom payload.
    if hasattr(user, 'profile'):
        payload['user_profile_id'] = user.profile.id if user.profile else None,

    # Include original issued at time for a brand new token
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = unix_epoch(issued_at_time)

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """

    return payload.get('user_id')


def jwt_get_username_from_payload_handler(payload):
    """
    Override this function if username is formatted differently in payload
    """

    return payload.get('username')


def jwt_encode_payload(payload):
    """Encode JWT token claims."""

    key = api_settings.JWT_PRIVATE_KEY or jwt_get_secret_key(payload)
    return force_text(jwt.encode(payload, key, api_settings.JWT_ALGORITHM))


def jwt_decode_token(token):
    """Decode JWT token claims."""

    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }
    # get user from token, BEFORE verification, to get user secret key
    unverified_payload = jwt.decode(token, None, False)
    secret_key = jwt_get_secret_key(unverified_payload)
    return jwt.decode(
        token, api_settings.JWT_PUBLIC_KEY or secret_key,
        api_settings.JWT_VERIFY, options=options,
        leeway=api_settings.JWT_LEEWAY, audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER, algorithms=[
            api_settings.JWT_ALGORITHM
        ]
    )


def jwt_create_response_payload(
        token, user=None, request=None, issued_at=None
):
    """
    Return data ready to be passed to serializer.

    Override this function if you need to include any additional data for
    serializer.

    Note that we are using `pk` field here - this is for forward compatibility
    with drf add-ons that might require `pk` field in order (eg. jsonapi).
    """

    response_payload = namedtuple('ResponsePayload', 'pk token')
    response_payload.pk = issued_at
    response_payload.token = token

    return response_payload
