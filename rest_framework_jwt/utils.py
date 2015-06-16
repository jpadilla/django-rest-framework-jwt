import jwt

from datetime import datetime

from rest_framework_jwt.settings import api_settings


def get_user_model():
    try:
        from django.contrib.auth import get_user_model
    except ImportError:  # Django < 1.5
        from django.contrib.auth.models import User
    else:
        User = get_user_model()

    return User


def get_salt_values_from_user(user):
    return tuple(getattr(user, attr) for attr
                 in api_settings.JWT_SALT_USER_ATTRIBUTES)


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
    }, get_salt_values_from_user(user)


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    user_id = payload.get('user_id')
    return user_id


def jwt_encode_handler(payload, salt=()):
    return jwt.encode(
        payload,
        ''.join((api_settings.JWT_SECRET_KEY,) + salt),
        api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):
    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }
    unsafe_payload = jwt.decode(token, verify=False)
    user_id = jwt_get_user_id_from_payload_handler(unsafe_payload)
    User = get_user_model()
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        salt = ()
    else:
        salt = get_salt_values_from_user(user)

    return jwt.decode(
        token,
        ''.join((api_settings.JWT_SECRET_KEY,) + salt),
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
