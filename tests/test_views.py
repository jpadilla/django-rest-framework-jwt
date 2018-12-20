# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.contrib.auth import get_user_model
from mock import patch

from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

from rest_framework.reverse import reverse
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from rest_framework.test import APITestCase

from rest_framework_jwt import settings
from tests.utils import \
    call_auth_endpoint, call_auth_refresh_endpoint, call_auth_verify_endpoint,\
    jwt_get_user_secret_key

from rest_framework_jwt.authentication import JSONWebTokenAuthentication

User = get_user_model()


def setup_default_mocked_api_settings(mock_settings):
    for setting_name, setting_value in settings.DEFAULTS.items():
        setattr(mock_settings, setting_name,
                getattr(settings.api_settings, setting_name))
    return mock_settings


class TestAuthViews(APITestCase):

    def setUp(self):
        self.active_user = User.objects.create_user(
            username='foobar', email='foobar@example.com', password='foo',
            is_active=True
        )
        self.inactive_user = User.objects.create_user(
            username='inactive', email='inactive@example.com', password='pass',
            is_active=False
        )

    def tearDown(self):
        # reset any leftover auth tokens
        self.client.credentials()

    def test_auth__empty_credentials__returns_validation_error(self):
        expected_output = {
            'password': [_('This field may not be blank.')],
            'username': [_('This field may not be blank.')]
        }

        response = call_auth_endpoint(self.client, "", "")

        self.assertEqual(response.json(), expected_output)

    def test_auth__invalid_credentials__returns_validation_error(self):
        expected_output = {
            'non_field_errors': [
                _('Unable to log in with provided credentials.')
            ]
        }

        response = call_auth_endpoint(
            self.client, "invalid_username", "invalid_password"
        )

        self.assertEqual(response.json(), expected_output)

    def test_auth__valid_credentials__returns_jwt_token(self):
        response = call_auth_endpoint(self.client, "foobar", "foo")

        token = response.json()['token']
        payload = JSONWebTokenAuthentication.jwt_decode_token(token)

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(payload['user_id'], self.active_user.id)
        self.assertEqual(payload['username'], self.active_user.get_username())

    @patch('rest_framework_jwt.utils.api_settings', autospec=True)
    def test_auth__valid_credentials_with_aud_and_iss_settings__returns_jwt_token(self, mock_settings):
        # Use default settings and override JWT_AUDIENCE and JWT_ISSUER settings
        mock_settings = setup_default_mocked_api_settings(mock_settings)
        mock_settings.JWT_AUDIENCE = 'test-aud'
        mock_settings.JWT_ISSUER = 'test-iss'

        response = call_auth_endpoint(self.client, "foobar", "foo")

        token = response.json()['token']
        payload = JSONWebTokenAuthentication.jwt_decode_token(token)

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(payload['aud'], mock_settings.JWT_AUDIENCE)
        self.assertEqual(payload['iss'], mock_settings.JWT_ISSUER)
        self.assertEqual(payload['user_id'], self.active_user.id)
        self.assertEqual(payload['username'], self.active_user.get_username())

    @patch('rest_framework_jwt.utils.api_settings', autospec=True)
    def test_auth__valid_credentials_with_JWT_GET_USER_SECRET_KEY_handler_set__returns_jwt_token(self, mock_settings):
        # Use default settings and override JWT_GET_USER_SECRET_KEY setting
        mock_settings = setup_default_mocked_api_settings(mock_settings)
        mock_settings.JWT_GET_USER_SECRET_KEY = jwt_get_user_secret_key

        response = call_auth_endpoint(self.client, "foobar", "foo")

        token = response.json()['token']
        payload = JSONWebTokenAuthentication.jwt_decode_token(token)

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(payload['user_id'], self.active_user.id)
        self.assertEqual(payload['username'], self.active_user.get_username())

    def test_auth__valid_credentials_inactive_user__returns_validation_error(self):
        expected_output = {
            'non_field_errors': [
                _('Unable to log in with provided credentials.')
            ]
        }

        response = call_auth_endpoint(self.client, "inactive", "pass")

        self.assertEqual(response.json(), expected_output)

    @patch('rest_framework_jwt.views.api_settings', autospec=True)
    def test_auth__valid_credentials_with_auth_cookie_settings__returns_jwt_token_and_cookie(
            self, mock_settings):

        auth_cookie = 'jwt-auth'
        # Use default settings and override JWT_AUTH_COOKIE setting
        mock_settings = setup_default_mocked_api_settings(mock_settings)
        mock_settings.JWT_AUTH_COOKIE = auth_cookie

        response = call_auth_endpoint(self.client, "foobar", "foo")

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertIn('token', force_text(response.content))
        self.assertIn(auth_cookie, response.client.cookies)

    def test_auth_verify__invalid_token__returns_validation_error(self):
        expected_output = {'non_field_errors': [_('Error decoding token.')]}

        response = call_auth_verify_endpoint(self.client, "invalid_token")

        self.assertEqual(response.json(), expected_output)

    def test_auth_verify__valid_token__returns_same_token(self):
        auth_response = call_auth_endpoint(self.client, "foobar", "foo")
        auth_token = auth_response.json()['token']

        verify_response = call_auth_verify_endpoint(self.client, auth_token)
        verify_token = verify_response.json()['token']

        self.assertEqual(verify_token, auth_token)

    def test_auth_verify__token_without_username__returns_validation_error(self):
        # create token without username field
        payload = JSONWebTokenAuthentication.jwt_create_payload(self.active_user)
        del payload['username']
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        expected_output = {'non_field_errors': [_('Invalid token.')]}

        verify_response = call_auth_verify_endpoint(self.client, auth_token)

        self.assertEqual(verify_response.json(), expected_output)

    def test_auth_verify__token_with_invalid_username__returns_validation_error(self):
        # create token with invalid username
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.active_user)
        payload['username'] = "i_do_not_exist"
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        expected_output = {'non_field_errors': [_("User doesn't exist.")]}

        verify_response = call_auth_verify_endpoint(self.client, auth_token)
        self.assertEqual(verify_response.json(), expected_output)

    def test_auth_verify__token_for_inactive_user__returns_validation_error(self):
        # create token with invalid username
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.inactive_user)
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        expected_output = {'non_field_errors': [_('User account is disabled.')]}

        verify_response = call_auth_verify_endpoint(self.client, auth_token)
        self.assertEqual(verify_response.json(), expected_output)

    def test_auth_verify__expired_token__returns_validation_error(self):

        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.active_user)
        payload['iat'] = 0  # beginning of time
        payload['exp'] = 1  # one second after beginning of time
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        expected_output = {'non_field_errors': [_('Token has expired.')]}

        verify_response = call_auth_verify_endpoint(self.client, auth_token)
        self.assertEqual(verify_response.json(), expected_output)

    def test_auth_refresh__invalid_token__returns_validation_error(self):
        expected_output = {'non_field_errors': [_('Error decoding token.')]}

        response = call_auth_refresh_endpoint(self.client, "invalid_token")
        self.assertEqual(response.json(), expected_output)

    @patch('rest_framework_jwt.utils.api_settings', autospec=True)
    def test_auth_refresh__with_JWT_ALLOW_REFRESH_disabled__returns_validation_error(self, mock_settings):
        mock_settings = setup_default_mocked_api_settings(mock_settings)
        mock_settings.JWT_ALLOW_REFRESH = False

        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.active_user)
        payload['exp'] = payload['iat'] + 100  # add 100 seconds to issued at time
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        expected_output = {
            'non_field_errors': ['orig_iat field not found in token.']
        }

        refresh_response = call_auth_refresh_endpoint(self.client, auth_token)

        self.assertEqual(refresh_response.json(), expected_output)


    def test_auth_refresh__without_orig_iat_in_payload__returns_validation_error(self):
        # create token without orig_iat in payload
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.active_user)
        del payload['orig_iat']
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        expected_output = {
            'non_field_errors': [_('orig_iat field not found in token.')]
        }

        response = call_auth_refresh_endpoint(self.client, auth_token)
        self.assertEqual(response.json(), expected_output)

    def test_auth_refresh__refresh_limit_expired__returns_validation_error(self):
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.active_user)
        payload['orig_iat'] = 0  # beginning of time
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        expected_output = {
            'non_field_errors': [_('Refresh has expired.')]
        }

        response = call_auth_refresh_endpoint(self.client, auth_token)
        self.assertEqual(response.json(), expected_output)

    def test_auth_refresh__valid_token__returns_new_token(self):
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.active_user)
        payload['exp'] = payload['iat'] + 100  # add 100 seconds to issued at time
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        refresh_response = call_auth_refresh_endpoint(self.client, auth_token)
        refresh_token = refresh_response.json()['token']
        self.assertNotEqual(refresh_token, auth_token)

    def test_auth_refresh__expired_token__returns_validation_error(self):
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.active_user)
        payload['iat'] = 0
        payload['exp'] = 1
        auth_token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        expected_output = {'non_field_errors': [_('Token has expired.')]}

        refresh_response = call_auth_refresh_endpoint(self.client, auth_token)
        self.assertEqual(refresh_response.json(), expected_output)


class TestAuthIntegration(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='foobar', email='foobar@example.com', password='foo',
            is_active=True
        )

    def tearDown(self):
        # reset any leftover auth tokens
        self.client.credentials()

    def test_view__unauthenticated(self):
        url = reverse('test-view')
        response = self.client.get(url)

        expected_output = {
            'detail': _("Authentication credentials were not provided.")
        }

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    def test_view__authenticated(self):
        auth_response = call_auth_endpoint(self.client, "foobar", "foo")
        token = auth_response.json()["token"]
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_200_OK)

    def test_view__invalid_token(self):
        token = 'invalid'
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        expected_output = {
            'detail': _("Error decoding token.")
        }

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    def test_view__expired_token(self):
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.user)
        payload['iat'] = 0
        payload['exp'] = 1
        token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        expected_output = {
            'detail': _("Token has expired.")
        }

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    def test_view__user_deactivated(self):
        payload = JSONWebTokenAuthentication.jwt_create_payload(self.user)
        token = JSONWebTokenAuthentication.jwt_encode_payload(payload)
        self.user.is_active = False
        self.user.save()

        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        expected_output = {
            'detail': _("User account is disabled.")
        }

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    def test_view__username_does_not_exist(self):
        # create token with invalid username
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.user)
        payload['username'] = "i_do_not_exist"
        token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        expected_output = {
            'detail': _("Invalid token.")
        }

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    def test_view__token_without_username(self):
        # create token without username
        payload = JSONWebTokenAuthentication.jwt_create_payload(
            self.user)
        del payload['username']
        token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        expected_output = {
            'detail': _("Invalid payload.")
        }

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    def test_view__authorization_header_without_token(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ')

        expected_output = {
            'detail':
                _("Invalid Authorization header. No credentials provided.")
        }

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    def test_view__authorization_header_token_with_spaces(self):
        payload = JSONWebTokenAuthentication.jwt_create_payload(self.user)
        token = JSONWebTokenAuthentication.jwt_encode_payload(payload)
        token = token.replace('.', ' ')

        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + token)

        expected_output = {
            'detail':
                _("Invalid Authorization header. Credentials string should "
                  "not contain spaces.")
        }

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    def test_view__authorization_head_with_invalid_token_prefix(self):
        payload = JSONWebTokenAuthentication.jwt_create_payload(self.user)
        token = JSONWebTokenAuthentication.jwt_encode_payload(payload)

        self.client.credentials(HTTP_AUTHORIZATION='INVALID_PREFIX ' + token)

        expected_output = {
            'detail':
                _("Authentication credentials were not provided.")
        }

        url = reverse('test-view')
        response = self.client.get(url)

        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.json(), expected_output)

    @patch('rest_framework_jwt.authentication.api_settings', autospec=True)
    @patch('rest_framework_jwt.views.api_settings', autospec=True)
    def test_view__auth_cookie(self, auth_mock_settings, views_mock_settings):
        auth_cookie = 'jwt-auth'
        # Use default settings and override JWT_AUTH_COOKIE setting
        auth_mock_settings = \
            setup_default_mocked_api_settings(auth_mock_settings)
        views_mock_settings = \
            setup_default_mocked_api_settings(views_mock_settings)
        auth_mock_settings.JWT_AUTH_COOKIE = auth_cookie
        views_mock_settings.JWT_AUTH_COOKIE = auth_cookie

        response = call_auth_endpoint(self.client, "foobar", "foo")

        url = reverse('test-view')
        response = response.client.get(url)

        self.assertEqual(response.status_code, HTTP_200_OK)
