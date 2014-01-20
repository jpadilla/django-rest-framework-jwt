from django.conf import settings
from rest_framework import exceptions
from rest_framework.authentication import (BaseAuthentication,
                                           get_authorization_header)

from rest_framework_jwt.settings import api_settings
from rest_framework_jwt import jwt

try:
    from django.contrib.auth import get_user_model
except ImportError: # django < 1.5
    from django.contrib.auth.models import User as UserModel
else:
    UserModel = get_user_model()


jwt_decode_handler = api_settings.DEFAULT_JWT_DECODE_HANDLER


class JSONWebTokenAuthentication(BaseAuthentication):
    """
    Token based authentication using the JSON Web Token standard.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Bearer ".  For example:

        Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'bearer':
            return None

        if len(auth) == 1:
            msg = 'Invalid bearer header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = ('Invalid bearer header. Credentials string '
                   'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            payload = jwt_decode_handler(auth[1])
        except jwt.ExpiredSignature:
            msg = 'Signature has expired.'
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = 'Error decoding signature.'
            raise exceptions.AuthenticationFailed(msg)

        user_id = payload['user_id']
        user_email = payload['email']
        user = self.authenticate_credentials(user_id, user_email)

        return (user, auth[1])

    def authenticate_credentials(self, user_id, email):
        """
        Returns an active user that matches the payload's user id and email.
        """
        try:
            user = UserModel.objects.get(pk=user_id, email=email, is_active=True)
        except UserModel.DoesNotExist:
            msg = 'Invalid signature'
            raise exceptions.AuthenticationFailed(msg)

        return user

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return 'Bearer realm="{0}"'.format(self.www_authenticate_realm)
