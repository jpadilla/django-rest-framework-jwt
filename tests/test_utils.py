import json
import base64
import pytest

import jwt.exceptions
from django.test import TestCase
from django.conf import settings

from rest_framework_jwt import utils
from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.settings import api_settings, DEFAULTS
from tests.models import CustomUserWithoutEmail
from tests.utils import custom_get_user_id, custom_get_user_secret

User = get_user_model()


def base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


class UtilsTests(TestCase):
    def setUp(self):
        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)

    def test_jwt_payload_handler(self):
        payload = utils.jwt_payload_handler(self.user)

        pytest.deprecated_call(utils.jwt_payload_handler, self.user)

        self.assertTrue(isinstance(payload, dict))
        self.assertEqual(payload['user_id'], self.user.pk)
        self.assertEqual(payload['email'], self.email)
        self.assertEqual(payload['username'], self.username)
        self.assertTrue('exp' in payload)

    def test_jwt_payload_handler_no_email_address(self):
        user = CustomUserWithoutEmail.objects.create(username=self.username)

        payload = utils.jwt_payload_handler(user)
        self.assertTrue(isinstance(payload, dict))
        self.assertFalse(hasattr(payload, 'email'))
        self.assertEqual(payload['user_id'], self.user.pk)
        self.assertEqual(payload['username'], self.username)
        self.assertTrue('exp' in payload)

    def test_jwt_encode(self):
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        payload_data = base64url_decode(token.split('.')[1].encode('utf-8'))
        payload_from_token = json.loads(payload_data.decode('utf-8'))

        self.assertEqual(payload_from_token, payload)

    def test_jwt_decode(self):
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)
        decoded_payload = utils.jwt_decode_handler(token)

        self.assertEqual(decoded_payload, payload)

    def test_jwt_response_payload(self):
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)
        response_data = utils.jwt_response_payload_handler(token)

        self.assertEqual(response_data, dict(token=token))

    def test_jwt_decode_verify_exp(self):
        api_settings.JWT_VERIFY_EXPIRATION = False

        payload = utils.jwt_payload_handler(self.user)
        payload['exp'] = 1
        token = utils.jwt_encode_handler(payload)
        utils.jwt_decode_handler(token)

        api_settings.JWT_VERIFY_EXPIRATION = True

    def test_jwt_get_secret_key(self):
        secret = utils.jwt_get_secret_key({'user_id': self.user.pk})
        self.assertEqual(secret, settings.SECRET_KEY)

    def test_jwt_get_secret_key_customer_secret_getter(self):
        old = api_settings.JWT_GET_USER_SECRET_KEY
        api_settings.JWT_GET_USER_SECRET_KEY = custom_get_user_secret
        secret = utils.jwt_get_secret_key({'user_id': self.user.pk})
        api_settings.JWT_GET_USER_SECRET_KEY = old
        self.assertEqual(secret, str(self.user.pk))

    def test_jwt_get_secret_key_customer_id_and_secret_getter(self):
        old = api_settings.JWT_GET_USER_SECRET_KEY
        api_settings.JWT_GET_USER_SECRET_KEY = custom_get_user_secret
        old2 = api_settings.JWT_PAYLOAD_GET_USER_ID_HANDLER
        api_settings.JWT_PAYLOAD_GET_USER_ID_HANDLER = custom_get_user_id
        secret = utils.jwt_get_secret_key({'custom_uid': self.user.pk})
        api_settings.JWT_PAYLOAD_GET_USER_ID_HANDLER = old2
        api_settings.JWT_GET_USER_SECRET_KEY = old
        self.assertEqual(secret, str(self.user.pk))


class TestAudience(TestCase):
    def setUp(self):
        api_settings.JWT_AUDIENCE = 'my_aud'

        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)

        return super(TestAudience, self).setUp()

    def test_fail_audience_missing(self):
        payload = utils.jwt_payload_handler(self.user)
        del payload['aud']
        token = utils.jwt_encode_handler(payload)
        with self.assertRaises(jwt.exceptions.MissingRequiredClaimError):
            utils.jwt_decode_handler(token)

    def test_fail_audience_wrong(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['aud'] = 'my_aud2'
        token = utils.jwt_encode_handler(payload)
        with self.assertRaises(jwt.exceptions.InvalidAudienceError):
            utils.jwt_decode_handler(token)

    def test_correct_audience(self):
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)
        decoded_payload = utils.jwt_decode_handler(token)
        self.assertEqual(decoded_payload, payload)

    def tearDown(self):
        api_settings.JWT_AUDIENCE = DEFAULTS['JWT_AUDIENCE']


class TestIssuer(TestCase):
    def setUp(self):
        api_settings.JWT_ISSUER = 'example.com'

        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)

        return super(TestIssuer, self).setUp()

    def test_fail_issuer_missing(self):
        payload = utils.jwt_payload_handler(self.user)
        del payload['iss']
        token = utils.jwt_encode_handler(payload)
        with self.assertRaises(jwt.exceptions.MissingRequiredClaimError):
            utils.jwt_decode_handler(token)

    def test_fail_issuer_wrong(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['iss'] = 'example2.com'
        token = utils.jwt_encode_handler(payload)
        with self.assertRaises(jwt.exceptions.InvalidIssuerError):
            utils.jwt_decode_handler(token)

    def test_correct_issuer(self):
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)
        decoded_payload = utils.jwt_decode_handler(token)
        self.assertEqual(decoded_payload, payload)

    def tearDown(self):
        api_settings.JWT_ISSUER = DEFAULTS['JWT_ISSUER']
