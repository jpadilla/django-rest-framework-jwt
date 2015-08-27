import jwt
import warnings
from calendar import timegm
from datetime import datetime

from django.core.exceptions import ImproperlyConfigured
from rest_framework_jwt.compat import get_username, get_username_field
from rest_framework_jwt.settings import api_settings


class JWTEncodeDecodeMixin(object):
    jwt_algorithms = None
    jwt_audience = None
    jwt_encode_algorithm = None
    jwt_issuer = None
    jwt_leeway = None
    jwt_secret_key = None
    jwt_verify = None
    jwt_verify_expiration = None

    def get_jwt_algorithms(self):
        if self.jwt_algorithms is None:
            return [api_settings.JWT_ALGORITHM]

        if not any([isinstance(self.jwt_algorithms, list),
                    self.jwt_algorithms]):
            raise ImproperlyConfigured(
                '{0}.jwt_algorithms property must be a list containing one '
                'or more supported algorithms'.format(
                    self.__class__.__name__))

        return self.jwt_algorithms

    def get_jwt_audience(self):
        if self.jwt_audience is None:
            return api_settings.JWT_AUDIENCE
        return self.jwt_audience

    def get_jwt_encode_algorithm(self):
        if self.jwt_encode_algorithm is None:
            return api_settings.JWT_ALGORITHM

        return self.jwt_encode_algorithm

    def get_jwt_issuer(self):
        if self.jwt_issuer is None:
            return api_settings.JWT_ISSUER

        return self.jwt_issuer

    def get_jwt_leeway(self):
        if self.jwt_leeway is None:
            return api_settings.JWT_LEEWAY

        if not isinstance(self.jwt_leeway, int):
            raise ImproperlyConfigured(
                '{0}.jwt_leeway must be a integer.'.format(
                    self.__class__.__name__))

        return self.jwt_leeway

    def get_jwt_secret_key(self):
        if self.jwt_secret_key is None:
            return api_settings.JWT_SECRET_KEY

        return self.jwt_secret_key

    def get_jwt_verify(self):
        if self.jwt_verify is None:
            return api_settings.JWT_VERIFY

        if not isinstance(self.jwt_verify, bool):
            raise ImproperlyConfigured(
                '{0}.jwt_verify must be a boolean.'.format(
                    self.__class__.__name__))

        return self.jwt_verify

    def get_jwt_verify_expiration(self):
        if self.jwt_verify_expiration is None:
            return api_settings.JWT_VERIFY_EXPIRATION

        if not isinstance(self.jwt_verify_expiration, bool):
            raise ImproperlyConfigured(
                '{0}.jwt_verify_expiration must be a boolean.'.format(
                    self.__class__.__name__))

        return self.jwt_verify_expiration

    def decode(self, token):
        options = {
            'verify_exp': self.get_jwt_verify_expiration()
        }

        return jwt.decode(
            token,
            self.get_jwt_secret_key(),
            self.get_jwt_verify(),
            options=options,
            leeway=self.get_jwt_leeway(),
            audience=self.get_jwt_audience(),
            issuer=self.get_jwt_issuer(),
            algorithms=self.get_jwt_algorithms()
        )

    def encode(self, payload):
        return jwt.encode(
            payload,
            self.get_jwt_secret_key(),
            self.get_jwt_encode_algorithm()
        ).decode('utf-8')


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

    payload[username_field] = username

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

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
