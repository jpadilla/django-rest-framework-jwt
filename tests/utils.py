from rest_framework_jwt.compat import get_username


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
        'user': get_username(user),
        'token': token
    }


def get_jwt_secret(user):
    return user.jwt_secret


def custom_get_user_secret(user):
    return user.pk


def custom_get_user_id(payload):
    return payload.get('custom_uid', None)
