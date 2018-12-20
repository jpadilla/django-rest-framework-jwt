# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import jwt

from django.contrib.auth import get_user_model
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _

from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header

from rest_framework_jwt.settings import api_settings


class JSONWebTokenAuthentication(BaseAuthentication):
    """
    Token based authentication using the JSON Web Token standard.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

        Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """

    www_authenticate_realm = 'api'

    @classmethod
    def jwt_create_payload(cls, *args, **kwargs):
        return api_settings.JWT_PAYLOAD_HANDLER(*args, **kwargs)

    @classmethod
    def jwt_encode_payload(cls, *args, **kwargs):
        return api_settings.JWT_ENCODE_HANDLER(*args, **kwargs)

    @classmethod
    def jwt_decode_token(cls, *args, **kwargs):
        return api_settings.JWT_DECODE_HANDLER(*args, **kwargs)

    @classmethod
    def jwt_get_username_from_payload(cls, *args, **kwargs):
        return api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER(*args, **kwargs)

    @classmethod
    def jwt_create_response_payload(cls, *args, **kwargs):
        return api_settings.JWT_RESPONSE_PAYLOAD_HANDLER(*args, **kwargs)

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """

        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = self.jwt_decode_token(jwt_value)
        except jwt.ExpiredSignature:
            msg = _('Token has expired.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = _('Error decoding token.')
            raise exceptions.AuthenticationFailed(msg)

        user = self.authenticate_credentials(payload)

        return user, jwt_value

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """

        username = self.jwt_get_username_from_payload(payload)

        if not username:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            User = get_user_model()
            user = User.objects.get_by_natural_key(username)
        except User.DoesNotExist:
            msg = _('Invalid token.')
            raise exceptions.AuthenticationFailed(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.AuthenticationFailed(msg)

        return user

    def get_jwt_value(self, request):
        """
        Extract JWT token from request Authorization header.

        Splits Authorization header string into a list where first member
        represents authorization prefix and second member represents JWT token.

        If Authorization header was empty checks if JWT token should be
        retrieved from cookie.

        After successful authorization header processing returns JWT token
        alone.
        """

        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth:
            if api_settings.JWT_AUTH_COOKIE:
                return request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
            return None

        if smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _(
                'Invalid Authorization header. Credentials string '
                'should not contain spaces.'
            )
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """

        return '{0} realm="{1}"'.format(
            api_settings.JWT_AUTH_HEADER_PREFIX, self.www_authenticate_realm
        )
