# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import jwt

from django.apps import apps
from django.contrib.auth import get_user_model
from django.utils.encoding import force_str

from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication,
    get_authorization_header,
)

from rest_framework_jwt.blacklist.exceptions import (
    InvalidAuthorizationCredentials,
    InvalidAuthorizationHeaderPrefix,
    MissingToken,
)
from rest_framework_jwt.blacklist.models import BlacklistedToken
from rest_framework_jwt.compat import gettext_lazy as _
from rest_framework_jwt.compat import smart_str
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
        try:
            token = self.get_token_from_request(request)
        except MissingToken:
            return None

        if apps.is_installed('rest_framework_jwt.blacklist'):
            if BlacklistedToken.objects.filter(token=force_str(token)).exists():
                msg = _('Token is blacklisted.')
                raise exceptions.PermissionDenied(msg)

        try:
            payload = self.jwt_decode_token(token)
        except jwt.ExpiredSignature:
            msg = _('Token has expired.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = _('Error decoding token.')
            raise exceptions.AuthenticationFailed(msg)

        user = self.authenticate_credentials(payload)

        return user, token

    @classmethod
    def get_token_from_request(cls, request):
        authorization_header = force_str(get_authorization_header(request))

        try:
            return cls.get_token_from_authorization_header(authorization_header)
        except InvalidAuthorizationHeaderPrefix as error:
            raise exceptions.AuthenticationFailed(error.msg)
        except InvalidAuthorizationCredentials:
            return cls.get_token_from_cookies(request.COOKIES)

    @classmethod
    def get_token_from_authorization_header(cls, authorization_header):
        try:
            prefix, token = authorization_header.split(' ')
        except ValueError:
            raise InvalidAuthorizationCredentials
        else:
            if not cls.prefixes_match(prefix):
                raise InvalidAuthorizationHeaderPrefix
            if not token:
                raise InvalidAuthorizationCredentials
            return token

    @classmethod
    def prefixes_match(cls, prefix):
        authorization_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        return smart_str(prefix.lower()) == authorization_header_prefix

    @classmethod
    def get_token_from_cookies(cls, cookies):
        if api_settings.JWT_IMPERSONATION_COOKIE:
            imp_user_token = cookies.get(api_settings.JWT_IMPERSONATION_COOKIE)
            if imp_user_token:
                return imp_user_token

        if api_settings.JWT_AUTH_COOKIE:
            try:
                return cookies[api_settings.JWT_AUTH_COOKIE]
            except KeyError:
                raise MissingToken

        raise MissingToken

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

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """

        return '{0} realm="{1}"'.format(
            api_settings.JWT_AUTH_HEADER_PREFIX, self.www_authenticate_realm
        )
