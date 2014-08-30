from datetime import datetime
import jwt

from rest_framework_jwt.settings import api_settings


def get_user_model():
    try:
        from django.contrib.auth import get_user_model
    except ImportError:  # django < 1.5
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
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA
    }


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
        api_settings.JWT_VERIFY_EXPIRATION,
        api_settings.JWT_LEEWAY
    )
