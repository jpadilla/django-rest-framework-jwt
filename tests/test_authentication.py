import unittest
import uuid

from .models import CustomUser

from .utils import get_jwt_secret
from django.test.utils import override_settings

from django.test import TestCase
from rest_framework import status
try:
    try:
        from rest_framework_oauth.compat import oauth2_provider
        from rest_framework_oauth.compat.oauth2_provider import oauth2
    except ImportError:
        # if oauth2 module can not be imported, skip the tests,
        # because models have not been initialized.
        oauth2_provider = None
except ImportError:
    try:
        from rest_framework.compat import oauth2_provider
        from rest_framework.compat.oauth2_provider import oauth2  # NOQA
    except ImportError:
        # if oauth2 module can not be imported, skip the tests,
        # because models have not been initialized.
        oauth2_provider = None

from rest_framework.test import APIClient
from rest_framework.test import APIRequestFactory

from rest_framework_jwt import utils
from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.settings import DEFAULTS
from rest_framework_jwt.settings import api_settings

User = get_user_model()

DJANGO_OAUTH2_PROVIDER_NOT_INSTALLED = 'django-oauth2-provider not installed'

factory = APIRequestFactory()


class JSONWebTokenAuthenticationTests(TestCase):
    """JSON Web Token Authentication"""

    def setUp(self):
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)

    def test_post_form_passing_jwt_auth(self):
        """
        Ensure POSTing form over JWT auth with correct credentials
        passes and does not require CSRF
        """
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b'mockview-post')

        # Ensure `authenticate` returned the decoded payload.
        self.assertEqual(response.wsgi_request.user, self.user)
        payload = response.wsgi_request.auth
        self.assertIsInstance(payload, dict)
        self.assertEqual(set(payload.keys()), {
            'user_id', 'username', 'exp', 'email'})

    def test_post_json_passing_jwt_auth(self):
        """
        Ensure POSTing JSON over JWT auth with correct credentials
        passes and does not require CSRF
        """
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_post_form_failing_jwt_auth(self):
        """
        Ensure POSTing form over JWT auth without correct credentials fails
        """
        response = self.csrf_client.post('/jwt/', {'example': 'example'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_json_failing_jwt_auth(self):
        """
        Ensure POSTing json over JWT auth without correct credentials fails
        """
        response = self.csrf_client.post('/jwt/', {'example': 'example'},
                                         format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_no_jwt_header_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth without credentials fails
        """
        auth = 'JWT'
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        msg = 'Invalid Authorization header. No credentials provided.'

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_invalid_jwt_header_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth without correct credentials fails
        """
        auth = 'JWT abc abc'
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        msg = ('Invalid Authorization header. Credentials string '
               'should not contain spaces.')

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_expired_token_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth with expired token fails
        """
        payload = utils.jwt_payload_handler(self.user)
        payload['exp'] = 1
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        msg = 'Signature has expired.'

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    @override_settings(AUTH_USER_MODEL='tests.CustomUser')
    def test_post_form_failing_jwt_auth_changed_user_secret_key(self):
        """
        Ensure changin secret key on USER level makes tokens invalid
        """
        # fine tune settings
        api_settings.JWT_GET_USER_SECRET_KEY = get_jwt_secret

        tmp_user = CustomUser.objects.create(email='b@example.com')
        payload = utils.jwt_payload_handler(tmp_user)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # change token, verify
        tmp_user.jwt_secret = uuid.uuid4()
        tmp_user.save()

        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # revert api settings
        api_settings.JWT_GET_USER_SECRET_KEY = DEFAULTS['JWT_GET_USER_SECRET_KEY']

    def test_post_invalid_token_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth with invalid token fails
        """
        auth = 'JWT abc123'
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        msg = 'Error decoding signature.'

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    @unittest.skipUnless(oauth2_provider, DJANGO_OAUTH2_PROVIDER_NOT_INSTALLED)
    def test_post_passing_jwt_auth_with_oauth2_priority(self):
        """
        Ensure POSTing over JWT auth with correct credentials
        passes and does not require CSRF when OAuth2Authentication
        has priority on authentication_classes
        """
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/oauth2-jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK, response)

    @unittest.skipUnless(oauth2_provider, DJANGO_OAUTH2_PROVIDER_NOT_INSTALLED)
    def test_post_passing_oauth2_with_jwt_auth_priority(self):
        """
        Ensure POSTing over OAuth2 with correct credentials
        passes and does not require CSRF when JSONWebTokenAuthentication
        has priority on authentication_classes
        """
        Client = oauth2_provider.oauth2.models.Client
        AccessToken = oauth2_provider.oauth2.models.AccessToken

        oauth2_client = Client.objects.create(
            user=self.user,
            client_type=0,
        )

        access_token = AccessToken.objects.create(
            user=self.user,
            client=oauth2_client,
        )

        auth = 'Bearer {0}'.format(access_token.token)
        response = self.csrf_client.post(
            '/jwt-oauth2/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK, response)

    def test_post_form_passing_jwt_invalid_payload(self):
        """
        Ensure POSTing json over JWT auth with invalid payload fails
        """
        payload = dict(email=None)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)

        msg = 'Invalid payload.'

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_different_auth_header_prefix(self):
        """
        Ensure using a different setting for `JWT_AUTH_HEADER_PREFIX` and
        with correct credentials passes.
        """
        api_settings.JWT_AUTH_HEADER_PREFIX = 'Bearer'

        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = 'Bearer {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Restore original settings
        api_settings.JWT_AUTH_HEADER_PREFIX = DEFAULTS['JWT_AUTH_HEADER_PREFIX']

    def test_post_form_failing_jwt_auth_different_auth_header_prefix(self):
        """
        Ensure using a different setting for `JWT_AUTH_HEADER_PREFIX` and
        POSTing form over JWT auth without correct credentials fails and
        generated correct WWW-Authenticate header
        """
        api_settings.JWT_AUTH_HEADER_PREFIX = 'Bearer'

        response = self.csrf_client.post('/jwt/', {'example': 'example'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'Bearer realm="api"')

        # Restore original settings
        api_settings.JWT_AUTH_HEADER_PREFIX = DEFAULTS['JWT_AUTH_HEADER_PREFIX']
