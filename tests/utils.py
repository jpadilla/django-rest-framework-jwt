from rest_framework_jwt.compat import get_username


def jwt_response_payload_handler(token, user=None, request=None, **kwargs):
    """
    Returns the response data for both the login and refresh views.
    Override to return a custom response such as including the
    serialized representation of the User.

    Example:

    def jwt_response_payload_handler(token, user=None, request=None, **kwargs):
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
