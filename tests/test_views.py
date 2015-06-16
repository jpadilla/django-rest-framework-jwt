from calendar import timegm
from datetime import datetime, timedelta

from django import get_version
from django.test import TestCase
from django.core.urlresolvers import reverse
from django.test.utils import override_settings
from django.utils import unittest
from django.conf.urls import patterns
from django.contrib.auth import get_user_model

from freezegun import freeze_time

from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from rest_framework_jwt import utils
from rest_framework_jwt.settings import api_settings, DEFAULTS
from rest_framework_jwt.refreshtoken.models import RefreshToken

from . import utils as test_utils

User = get_user_model()

NO_CUSTOM_USER_MODEL = 'Custom User Model only supported after Django 1.5'

urlpatterns = patterns(
    '',
    (r'^auth-token/$', 'rest_framework_jwt.views.obtain_jwt_token'),
    (r'^auth-token-refresh/$', 'rest_framework_jwt.views.refresh_jwt_token'),
    (r'^auth-token-verify/$', 'rest_framework_jwt.views.verify_jwt_token'),

)

orig_datetime = datetime


class BaseTestCase(TestCase):
    urls = 'tests.test_views'

    def setUp(self):
        self.email = 'jpueblo@example.com'
        self.username = 'jpueblo'
        self.password = 'password'
        self.user = User.objects.create_user(
            self.username, self.email, self.password)

        self.data = {
            'username': self.username,
            'password': self.password
        }


class TestCustomResponsePayload(BaseTestCase):
    def setUp(self):
        api_settings.JWT_RESPONSE_PAYLOAD_HANDLER = test_utils.\
            jwt_response_payload_handler
        return super(TestCustomResponsePayload, self).setUp()

    def test_jwt_login_custom_response_json(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        response = client.post('/auth-token/', self.data, format='json')

        decoded_payload = utils.jwt_decode_handler(response.data['token'])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(decoded_payload['username'], self.username)
        self.assertEqual(response.data['user'], self.username)

    def tearDown(self):
        api_settings.JWT_RESPONSE_PAYLOAD_HANDLER =\
            DEFAULTS['JWT_RESPONSE_PAYLOAD_HANDLER']


class ObtainJSONWebTokenTests(BaseTestCase):

    def test_jwt_login_json(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        response = client.post('/auth-token/', self.data, format='json')

        decoded_payload = utils.jwt_decode_handler(response.data['token'])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(decoded_payload['username'], self.username)

    def test_jwt_login_json_bad_creds(self):
        """
        Ensure JWT login view using JSON POST fails
        if bad credentials are used.
        """
        client = APIClient(enforce_csrf_checks=True)

        self.data['password'] = 'wrong'
        response = client.post('/auth-token/', self.data, format='json')

        self.assertEqual(response.status_code, 400)

    def test_jwt_login_json_missing_fields(self):
        """
        Ensure JWT login view using JSON POST fails if missing fields.
        """
        client = APIClient(enforce_csrf_checks=True)

        response = client.post('/auth-token/',
                               {'username': self.username}, format='json')

        self.assertEqual(response.status_code, 400)

    def test_jwt_login_form(self):
        """
        Ensure JWT login view using form POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        response = client.post('/auth-token/', self.data)

        decoded_payload = utils.jwt_decode_handler(response.data['token'])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(decoded_payload['username'], self.username)

    def test_jwt_login_with_expired_token(self):
        """
        Ensure JWT login view works even if expired token is provided
        """
        payload = utils.jwt_payload_handler(self.user)
        payload['exp'] = 1
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        client = APIClient(enforce_csrf_checks=True)
        response = client.post(
            '/auth-token/', self.data,
            HTTP_AUTHORIZATION=auth, format='json')

        decoded_payload = utils.jwt_decode_handler(response.data['token'])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(decoded_payload['username'], self.username)

    def test_jwt_login_using_zero(self):
        """
        Test to reproduce issue #33
        """
        client = APIClient(enforce_csrf_checks=True)

        data = {
            'username': '0',
            'password': '0'
        }

        response = client.post('/auth-token/', data, format='json')

        self.assertEqual(response.status_code, 400)


@unittest.skipIf(get_version() < '1.5.0', 'No Configurable User model feature')
@override_settings(AUTH_USER_MODEL='tests.CustomUser')
class CustomUserObtainJSONWebTokenTests(TestCase):
    """JSON Web Token Authentication"""
    urls = 'tests.test_views'

    def setUp(self):
        from .models import CustomUser

        self.email = 'jpueblo@example.com'
        self.password = 'password'
        user = CustomUser.objects.create(email=self.email)
        user.set_password(self.password)
        user.save()
        self.user = user

        self.data = {
            'email': self.email,
            'password': self.password
        }

    def test_jwt_login_json(self):
        """
        Ensure JWT login view using JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)

        response = client.post('/auth-token/', self.data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        decoded_payload = utils.jwt_decode_handler(response.data['token'])
        self.assertEqual(decoded_payload['username'], self.email)

    def test_jwt_login_json_bad_creds(self):
        """
        Ensure JWT login view using JSON POST fails
        if bad credentials are used.
        """
        client = APIClient(enforce_csrf_checks=True)

        self.data['password'] = 'wrong'
        response = client.post('/auth-token/', self.data, format='json')

        self.assertEqual(response.status_code, 400)


class TokenTestCase(BaseTestCase):
    """
    Handlers for getting tokens from the API, or creating arbitrary ones.
    """

    def get_token(self):
        client = APIClient(enforce_csrf_checks=True)
        response = client.post('/auth-token/', self.data, format='json')
        return response.data['token']

    def create_token(self, user, exp=None, orig_iat=None):
        payload = utils.jwt_payload_handler(user)
        if exp:
            payload['exp'] = exp

        if orig_iat:
            payload['orig_iat'] = timegm(orig_iat.utctimetuple())

        token = utils.jwt_encode_handler(payload)
        return token


class VerifyJSONWebTokenTests(TokenTestCase):

    def test_verify_jwt(self):
        """
        Test that a valid, non-expired token will return a 200 response
        and itself when passed to the validation endpoint.
        """
        client = APIClient(enforce_csrf_checks=True)

        with freeze_time('2015-01-01 00:00:01'):
            orig_token = self.get_token()

            with freeze_time('2015-01-01 00:00:10'):
                # Now try to get a refreshed token
                response = client.post('/auth-token-verify/', {'token': orig_token},
                                       format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data['token'], orig_token)

    def test_verify_jwt_fails_with_expired_token(self):
        """
        Test that an expired token will fail with the correct error.
        """
        client = APIClient(enforce_csrf_checks=True)

        # Make an expired token..
        token = self.create_token(
            self.user,
            exp=datetime.utcnow() - timedelta(seconds=5),
            orig_iat=datetime.utcnow() - timedelta(hours=1)
        )

        response = client.post('/auth-token-verify/', {'token': token},
                               format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertRegexpMatches(response.data['non_field_errors'][0],
                                 'Signature has expired')

    def test_verify_jwt_fails_with_bad_token(self):
        """
        Test that an invalid token will fail with the correct error.
        """
        client = APIClient(enforce_csrf_checks=True)

        token = "i am not a correctly formed token"

        response = client.post('/auth-token-verify/', {'token': token},
                               format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertRegexpMatches(response.data['non_field_errors'][0],
                                 'Error decoding signature')

    def test_verify_jwt_fails_with_missing_user(self):
        """
        Test that an invalid token will fail with a user that does not exist.
        """
        client = APIClient(enforce_csrf_checks=True)

        user = User.objects.create_user(
            email='jsmith@example.com', username='jsmith', password='password')

        token = self.create_token(user)
        # Delete the user used to make the token
        user.delete()

        response = client.post('/auth-token-verify/', {'token': token},
                               format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertRegexpMatches(response.data['non_field_errors'][0],
                                 "User doesn't exist")


class RefreshJSONWebTokenTests(TokenTestCase):

    def setUp(self):
        super(RefreshJSONWebTokenTests, self).setUp()
        api_settings.JWT_ALLOW_REFRESH = True

    def test_refresh_jwt(self):
        """
        Test getting a refreshed token from original token works
        """
        client = APIClient(enforce_csrf_checks=True)

        with freeze_time('2015-01-01 00:00:01'):
            orig_token = self.get_token()
            orig_token_decoded = utils.jwt_decode_handler(orig_token)

            expected_orig_iat = timegm(datetime.utcnow().utctimetuple())

            # Make sure 'orig_iat' exists and is the current time (give some slack)
            orig_iat = orig_token_decoded['orig_iat']
            self.assertLessEqual(orig_iat - expected_orig_iat, 1)

            with freeze_time('2015-01-01 00:00:03'):

                # Now try to get a refreshed token
                response = client.post('/auth-token-refresh/', {'token': orig_token},
                                       format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)

            new_token = response.data['token']
            new_token_decoded = utils.jwt_decode_handler(new_token)

        # Make sure 'orig_iat' on the new token is same as original
        self.assertEquals(new_token_decoded['orig_iat'], orig_iat)
        self.assertGreater(new_token_decoded['exp'], orig_token_decoded['exp'])

    def test_refresh_jwt_after_refresh_expiration(self):
        """
        Test that token can't be refreshed after token refresh limit
        """
        client = APIClient(enforce_csrf_checks=True)

        orig_iat = (datetime.utcnow() - api_settings.JWT_REFRESH_EXPIRATION_DELTA -
                    timedelta(seconds=5))
        token = self.create_token(
            self.user,
            exp=datetime.utcnow() + timedelta(hours=1),
            orig_iat=orig_iat
        )

        response = client.post('/auth-token-refresh/', {'token': token},
                               format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['non_field_errors'][0],
                         'Refresh has expired.')

    def tearDown(self):
        # Restore original settings
        api_settings.JWT_ALLOW_REFRESH = DEFAULTS['JWT_ALLOW_REFRESH']


class RefreshTokenTestCase(APITestCase):
    urls = 'rest_framework_jwt.refreshtoken.routers'

    def setUp(self):
        self.email = 'jpueblo@example.com'
        self.username = 'jpueblo'
        self.password = 'password'
        self.user = User.objects.create_user(
            self.username, self.email, self.password)
        self.token = RefreshToken.objects.create(user=self.user, app='test-app')
        email1 = 'jonny@example.com'
        username1 = 'jonnytestpants'
        password1 = 'password'
        self.user1 = User.objects.create_user(username1, email1, password1)
        self.token1 = RefreshToken.objects.create(user=self.user1, app='another-app')

        self.list_url = reverse('refreshtoken-list')
        self.detail_url = reverse(
            'refreshtoken-detail',
            kwargs={'key': self.token.key}
        )
        self.detail_url1 = reverse(
            'refreshtoken-detail',
            kwargs={'key': self.token1.key}
        )
        self.delegate_url = reverse('delegate-tokens')

    def test_requires_auth(self):
        response = self.client.get(self.list_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
            (response.status_code, response.content)
        )

        response = self.client.get(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
            (response.status_code, response.content)
        )

        response = self.client.delete(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
            (response.status_code, response.content)
        )

        response = self.client.post(self.list_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
            (response.status_code, response.content)
        )

    def test_get_refresh_token_list(self):
        self.client.force_authenticate(self.user)
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.data), 1)
        resp0 = response.data[0]
        self.assertEqual(self.token.key, resp0['key'])

        self.client.force_authenticate(self.user1)
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.data), 1)
        resp0 = response.data[0]
        self.assertEqual(self.token1.key, resp0['key'])

        self.assertEqual(RefreshToken.objects.count(), 2)

    def test_get_refresth_token_detail(self):
        self.client.force_authenticate(self.user)
        response = self.client.get(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
            (response.status_code, response.content)
        )
        response = self.client.get(self.detail_url1)
        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
            (response.status_code, response.content)
        )

    def test_delete_refresth_token(self):
        self.client.force_authenticate(self.user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
            (response.status_code, response.content)
        )
        response = self.client.delete(self.detail_url1)
        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
            (response.status_code, response.content)
        )

    def test_create_refresth_token(self):
        self.client.force_authenticate(self.user)
        data = {
            'app': 'gandolf'
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
            (response.status_code, response.content)
        )
        self.assertEqual(response.data['user'], self.user.pk)
        self.assertEqual(response.data['app'], data['app'])

    def test_delegate_jwt(self):
        headers = {'HTTP_AUTHORIZATION': 'RefreshToken {}'.format(self.token1.key)}
        response = self.client.post(self.delegate_url, format='json', **headers)
        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
            (response.status_code, response.content)
        )
        self.assertIn('token', response.data)
