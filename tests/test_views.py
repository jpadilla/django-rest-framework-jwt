# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import datetime
import time

from mock import patch

from django.contrib.auth.models import User
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

from rest_framework.status import HTTP_200_OK
from rest_framework.test import APITestCase

from rest_framework_jwt import settings
from tests.utils import \
    call_auth_endpoint, call_auth_refresh_endpoint, call_auth_verify_endpoint


class TestAuthViews(APITestCase):

    def setUp(self):
        self.USER = User.objects.create_user(
            username='foobar', email='foobar@example.com', password='foo',
            is_active=True
        )

    def test_auth__invalid_credentials__returns_validation_error(self):
        EXPECTED_OUTPUT = {
            'non_field_errors': [
                _('Unable to log in with provided credentials.')
            ]
        }

        response = call_auth_endpoint(
            self.client, "invalid_username", "invalid_password"
        )

        self.assertEqual(response.json(), EXPECTED_OUTPUT)

    def test_auth__valid_credentials__returns_jwt_token_and_user_details(self):
        response = call_auth_endpoint(self.client, "foobar", "foo")

        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertIn('token', force_text(response.content))

    def test_auth_verify__invalid_token__returns_validation_error(self):
        EXPECTED_OUTPUT = {'non_field_errors': [_('Error decoding token.')]}

        response = call_auth_verify_endpoint(self.client, "invalid_token")

        self.assertEqual(response.json(), EXPECTED_OUTPUT)

    def test_auth_verify__valid_token__returns_same_token(self):
        auth_response = call_auth_endpoint(self.client, "foobar", "foo")
        auth_token = auth_response.json()['token']

        verify_response = call_auth_verify_endpoint(self.client, auth_token)
        verify_token = verify_response.json()['token']
        self.assertEqual(verify_token, auth_token)

    @patch('rest_framework_jwt.utils.api_settings', autospec=True)
    def test_auth_verify__expired_token__returns_validation_error(
            self, mock_settings
    ):
        # Use default settings and override JWT_EXPIRATION_DELTA setting
        for setting_name, setting_value in settings.DEFAULTS.items():
            setattr(mock_settings, setting_name, setting_value)
        mock_settings.JWT_EXPIRATION_DELTA = datetime.timedelta(seconds=2)

        EXPECTED_OUTPUT = {'non_field_errors': [_('Token has expired.')]}

        auth_response = call_auth_endpoint(self.client, "foobar", "foo")
        auth_token = auth_response.json()['token']

        # wait for token to expire
        time.sleep(3)

        verify_response = call_auth_verify_endpoint(self.client, auth_token)
        self.assertEqual(verify_response.json(), EXPECTED_OUTPUT)

    def test_auth_refresh__invalid_token__returns_validation_error(self):
        EXPECTED_OUTPUT = {'non_field_errors': [_('Error decoding token.')]}

        response = call_auth_refresh_endpoint(self.client, "invalid_token")
        self.assertEqual(response.json(), EXPECTED_OUTPUT)

    def test_auth_refresh__valid_token__returns_new_token(self):
        auth_response = call_auth_endpoint(self.client, "foobar", "foo")
        auth_token = auth_response.json()['token']

        # wait just enough time to be able to refresh token while the old token
        # is still valid
        time.sleep(1)

        refresh_response = call_auth_refresh_endpoint(self.client, auth_token)
        refresh_token = refresh_response.json()['token']
        self.assertNotEqual(refresh_token, auth_token)

    @patch('rest_framework_jwt.utils.api_settings', autospec=True)
    def test_auth_refresh__expired_token__returns_validation_error(
            self, mock_settings
    ):
        # Use default settings and override JWT_EXPIRATION_DELTA setting
        for setting_name, setting_value in settings.DEFAULTS.items():
            setattr(mock_settings, setting_name, setting_value)
        mock_settings.JWT_EXPIRATION_DELTA = datetime.timedelta(seconds=2)

        EXPECTED_OUTPUT = {'non_field_errors': [_('Token has expired.')]}

        auth_response = call_auth_endpoint(self.client, "foobar", "foo")
        auth_token = auth_response.json()['token']

        # wait until token expires
        time.sleep(3)

        refresh_response = call_auth_refresh_endpoint(self.client, auth_token)
        self.assertEqual(refresh_response.json(), EXPECTED_OUTPUT)
