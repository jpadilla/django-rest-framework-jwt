from calendar import timegm
from datetime import datetime, timedelta
import time

from django.test import TestCase
from django.conf import settings
from django.contrib.auth.models import User

from rest_framework import status
from rest_framework.compat import patterns
from rest_framework.test import APIClient

from rest_framework_jwt import utils
from rest_framework_jwt.runtests.models import CustomUser
from rest_framework_jwt.settings import api_settings, DEFAULTS

urlpatterns = patterns(
    '',
    (r'^auth-token/$', 'rest_framework_jwt.views.obtain_jwt_token'),
    (r'^auth-token-refresh/$', 'rest_framework_jwt.views.refresh_jwt_token'),
)

orig_datetime = datetime


class BaseTestCase(TestCase):
    urls = 'rest_framework_jwt.tests.test_views'

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


class CustomUserObtainJSONWebTokenTests(TestCase):
    """JSON Web Token Authentication"""
    urls = 'rest_framework_jwt.tests.test_views'

    def setUp(self):
        # set custom user model
        self.ORIG_AUTH_USER_MODEL = settings.AUTH_USER_MODEL
        settings.AUTH_USER_MODEL = 'runtests.CustomUser'

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

    def tearDown(self):
        settings.AUTH_USER_MODEL = self.ORIG_AUTH_USER_MODEL


class RefreshJSONWebTokenTests(BaseTestCase):
    urls = 'rest_framework_jwt.tests.test_views'

    def setUp(self):
        super(RefreshJSONWebTokenTests, self).setUp()
        api_settings.JWT_ALLOW_REFRESH = True

    def get_token(self):
        client = APIClient(enforce_csrf_checks=True)
        response = client.post('/auth-token/', self.data, format='json')
        return response.data['token']

    def create_token(self, user, exp=None, orig_iat=None):
        payload = utils.jwt_payload_handler(self.user)
        if exp:
            payload['exp'] = exp

        if orig_iat:
            payload['orig_iat'] = timegm(orig_iat.utctimetuple())

        token = utils.jwt_encode_handler(payload)
        return token

    def test_refresh_jwt(self):
        """
        Test getting a refreshed token from original token works
        """
        client = APIClient(enforce_csrf_checks=True)

        orig_token = self.get_token()
        orig_token_decoded = utils.jwt_decode_handler(orig_token)

        expected_orig_iat = timegm(datetime.utcnow().utctimetuple())

        # Make sure 'orig_iat' exists and is the current time (give some slack)
        orig_iat = orig_token_decoded['orig_iat']
        self.assertLessEqual(orig_iat - expected_orig_iat, 1)

        # wait a few seconds, so new token will have different exp
        time.sleep(2)

        # Now try to get a refreshed token
        response = client.post('/auth-token-refresh/', {'token': orig_token},
                               format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        new_token = response.data['token']
        new_token_decoded = utils.jwt_decode_handler(new_token)

        # Make sure 'orig_iat' on the new token is same as original
        self.assertEquals(new_token_decoded['orig_iat'], orig_iat)
        self.assertGreater(new_token_decoded['exp'], orig_token_decoded['exp'])

    def test_refresh_jwt_fails_with_expired_token(self):
        """
        Test that using an expired token to refresh won't work
        """
        client = APIClient(enforce_csrf_checks=True)

        # Make an expired token..
        token = self.create_token(
            self.user,
            exp=datetime.utcnow() - timedelta(seconds=5),
            orig_iat=datetime.utcnow() - timedelta(hours=1)
        )

        response = client.post('/auth-token-refresh/', {'token': token},
                               format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertRegexpMatches(response.data['non_field_errors'][0],
                                 'Signature has expired')

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
                         'Refresh has expired')

    def tearDown(self):
        # Restore original settings
        api_settings.JWT_ALLOW_REFRESH = \
            DEFAULTS['JWT_ALLOW_REFRESH']
