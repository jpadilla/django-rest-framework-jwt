import json
import base64

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework_jwt import utils

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
        response_data = utils.jwt_response_payload_handler(token, self.user)

        self.assertEqual(response_data, dict(token=token))
