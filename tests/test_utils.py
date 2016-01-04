import base64
import json
import pytest

import jwt.exceptions
from django.test import TestCase

from rest_framework_jwt import utils
from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.settings import api_settings, DEFAULTS

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
        self.encode_decode_mixin = utils.JWTEncodeDecodeMixin()

    def test_jwt_payload_handler(self):
        payload = utils.jwt_payload_handler(self.user)

        pytest.deprecated_call(utils.jwt_payload_handler, self.user)

        self.assertTrue(isinstance(payload, dict))
        self.assertEqual(payload['user_id'], self.user.pk)
        self.assertEqual(payload['email'], self.email)
        self.assertEqual(payload['username'], self.username)
        self.assertTrue('exp' in payload)

    def test_jwt_encode(self):
        payload = utils.jwt_payload_handler(self.user)
        token = self.encode_decode_mixin.encode(payload)

        payload_data = base64url_decode(token.split('.')[1].encode('utf-8'))
        payload_from_token = json.loads(payload_data.decode('utf-8'))

        self.assertEqual(payload_from_token, payload)

    def test_jwt_decode(self):
        payload = utils.jwt_payload_handler(self.user)
        token = self.encode_decode_mixin.encode(payload)
        decoded_payload = self.encode_decode_mixin.decode(token)

        self.assertEqual(decoded_payload, payload)

    def test_jwt_response_payload(self):
        payload = utils.jwt_payload_handler(self.user)
        token = self.encode_decode_mixin.encode(payload)
        response_data = utils.jwt_response_payload_handler(token)

        self.assertEqual(response_data, dict(token=token))

    def test_jwt_decode_verify_exp(self):
        api_settings.JWT_VERIFY_EXPIRATION = False

        payload = utils.jwt_payload_handler(self.user)
        payload['exp'] = 1
        token = self.encode_decode_mixin.encode(payload)
        self.encode_decode_mixin.decode(token)

        api_settings.JWT_VERIFY_EXPIRATION = True


class TestAudience(TestCase):
    def setUp(self):
        api_settings.JWT_AUDIENCE = "my_aud"

        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)
        self.encode_decode_mixin = utils.JWTEncodeDecodeMixin()

        return super(TestAudience, self).setUp()

    def test_fail_audience_missing(self):
        payload = utils.jwt_payload_handler(self.user)
        token = self.encode_decode_mixin.encode(payload)
        with self.assertRaises(jwt.exceptions.MissingRequiredClaimError):
            self.encode_decode_mixin.decode(token)

    def test_fail_audience_wrong(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['aud'] = "my_aud2"
        token = self.encode_decode_mixin.encode(payload)
        with self.assertRaises(jwt.exceptions.InvalidAudienceError):
            self.encode_decode_mixin.decode(token)

    def test_correct_audience(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['aud'] = "my_aud"
        token = self.encode_decode_mixin.encode(payload)
        decoded_payload = self.encode_decode_mixin.decode(token)

        self.assertEqual(decoded_payload, payload)

    def tearDown(self):
        api_settings.JWT_AUDIENCE = DEFAULTS['JWT_AUDIENCE']


class TestIssuer(TestCase):
    def setUp(self):
        api_settings.JWT_ISSUER = "example.com"

        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)
        self.encode_decode_mixin = utils.JWTEncodeDecodeMixin()

        return super(TestIssuer, self).setUp()

    def test_fail_issuer_missing(self):
        payload = utils.jwt_payload_handler(self.user)
        token = self.encode_decode_mixin.encode(payload)
        with self.assertRaises(jwt.exceptions.MissingRequiredClaimError):
            self.encode_decode_mixin.decode(token)

    def test_fail_issuer_wrong(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['iss'] = "example2.com"
        token = self.encode_decode_mixin.encode(payload)
        with self.assertRaises(jwt.exceptions.InvalidIssuerError):
            self.encode_decode_mixin.decode(token)

    def test_correct_issuer(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['iss'] = "example.com"
        token = self.encode_decode_mixin.encode(payload)
        decoded_payload = self.encode_decode_mixin.decode(token)
        self.assertEqual(decoded_payload, payload)

    def tearDown(self):
        api_settings.JWT_ISSUER = DEFAULTS['JWT_ISSUER']
