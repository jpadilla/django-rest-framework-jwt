import json
import time
import base64
import jwt.exceptions

from django.db import models
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from django.test import TestCase

from rest_framework_jwt import utils
from rest_framework_jwt.settings import api_settings, DEFAULTS
from rest_framework_jwt.blacklist import utils as blacklist_utils
from rest_framework_jwt.blacklist.models import JWTBlacklistToken

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

        self.assertTrue(isinstance(payload, dict))
        self.assertEqual(payload['user_id'], self.user.pk)
        self.assertEqual(payload['email'], self.email)
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

    def test_jwt_blacklist_get_success(self):
        payload = utils.jwt_payload_handler(self.user)

        # Create blacklisted token.
        token_created = JWTBlacklistToken.objects.create(
            jti=payload.get('jti'),
            expires=now(),
            created=now()
        )

        token_fetched = blacklist_utils.jwt_blacklist_get_handler(payload)

        if hasattr(models, 'UUIDField'):
            self.assertEqual(token_created.jti, token_fetched.jti.hex)
        else:
            self.assertEqual(token_created.jti, token_fetched.jti)

    def test_jwt_blacklist_get_fail(self):
        payload = utils.jwt_payload_handler(self.user)

        # Test that incoming empty jti fails.
        payload['jti'] = None

        token_fetched = blacklist_utils.jwt_blacklist_get_handler(payload)

        self.assertIsNone(token_fetched)

    def test_jwt_blacklist_set_success(self):
        payload = utils.jwt_payload_handler(self.user)

        # exp field comes in as seconds since epoch
        payload['exp'] = int(time.time())

        # Create blacklisted token.
        token = blacklist_utils.jwt_blacklist_set_handler(payload)

        self.assertEqual(token.jti, payload.get('jti'))

    def test_jwt_blacklist_set_fail(self):
        payload = utils.jwt_payload_handler(self.user)

        # Create blacklisted token.
        token = blacklist_utils.jwt_blacklist_set_handler(payload)

        self.assertIsNone(token)

    def test_jwt_decode_verify_exp(self):
        api_settings.JWT_VERIFY_EXPIRATION = False

        payload = utils.jwt_payload_handler(self.user)
        payload['exp'] = 1
        token = utils.jwt_encode_handler(payload)
        utils.jwt_decode_handler(token)

        api_settings.JWT_VERIFY_EXPIRATION = True


class TestAudience(TestCase):
    def setUp(self):
        api_settings.JWT_AUDIENCE = "my_aud"

        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)

        return super(TestAudience, self).setUp()

    def test_fail_audience_missing(self):
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)
        with self.assertRaises(jwt.exceptions.InvalidAudienceError):
            utils.jwt_decode_handler(token)

    def test_fail_audience_wrong(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['aud'] = "my_aud2"
        token = utils.jwt_encode_handler(payload)
        with self.assertRaises(jwt.exceptions.InvalidAudienceError):
            utils.jwt_decode_handler(token)

    def test_correct_audience(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['aud'] = "my_aud"
        token = utils.jwt_encode_handler(payload)
        decoded_payload = utils.jwt_decode_handler(token)
        self.assertEqual(decoded_payload, payload)

    def tearDown(self):
        api_settings.JWT_AUDIENCE = DEFAULTS['JWT_AUDIENCE']


class TestIssuer(TestCase):
    def setUp(self):
        api_settings.JWT_ISSUER = "example.com"

        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)

        return super(TestIssuer, self).setUp()

    def test_fail_issuer_missing(self):
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)
        with self.assertRaises(jwt.exceptions.InvalidIssuerError):
            utils.jwt_decode_handler(token)

    def test_fail_issuer_wrong(self):
        payload = utils.jwt_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)
        payload['iss'] = "example2.com"
        with self.assertRaises(jwt.exceptions.InvalidIssuerError):
            utils.jwt_decode_handler(token)

    def test_correct_issuer(self):
        payload = utils.jwt_payload_handler(self.user)
        payload['iss'] = "example.com"
        token = utils.jwt_encode_handler(payload)
        decoded_payload = utils.jwt_decode_handler(token)
        self.assertEqual(decoded_payload, payload)

    def tearDown(self):
        api_settings.JWT_ISSUER = DEFAULTS['JWT_ISSUER']
