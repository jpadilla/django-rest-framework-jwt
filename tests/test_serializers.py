import unittest
from distutils.version import StrictVersion

import django
import rest_framework
from django.test import TestCase
from rest_framework_jwt import utils
from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.serializers import JSONWebTokenSerializer

User = get_user_model()

drf2 = rest_framework.VERSION < StrictVersion('3.0.0')
drf3 = rest_framework.VERSION >= StrictVersion('3.0.0')
django110 = django.get_version() >= StrictVersion('1.10.0')
django_110_skip = """django.contrib.auth.backends.ModelBackend.authenticate
                     method is different in Django 1.10 if user is not valid
                     then authenticate will return None
                     """


class JSONWebTokenSerializerTests(TestCase):
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

    @unittest.skipUnless(drf2, 'not supported in this version')
    def test_empty_drf2(self):
        serializer = JSONWebTokenSerializer()
        expected = {
            'username': ''
        }

        self.assertEqual(serializer.data, expected)

    @unittest.skipUnless(drf3, 'not supported in this version')
    def test_empty_drf3(self):
        serializer = JSONWebTokenSerializer()
        expected = {
            'username': '',
            'password': ''
        }

        self.assertEqual(serializer.data, expected)

    def test_create(self):
        serializer = JSONWebTokenSerializer(data=self.data)
        is_valid = serializer.is_valid()

        token = serializer.object['token']
        decoded_payload = utils.jwt_decode_handler(token)

        self.assertTrue(is_valid)
        self.assertEqual(decoded_payload['username'], self.username)

    def test_invalid_credentials(self):
        self.data['password'] = 'wrong'
        serializer = JSONWebTokenSerializer(data=self.data)
        is_valid = serializer.is_valid()

        expected_error = {
            'non_field_errors': ['Unable to login with provided credentials.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)

    @unittest.skipIf(django110, django_110_skip)
    def test_disabled_user(self):
        self.user.is_active = False
        self.user.save()

        serializer = JSONWebTokenSerializer(data=self.data)
        is_valid = serializer.is_valid()

        expected_error = {
            'non_field_errors': ['User account is disabled.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)

    def test_required_fields(self):
        serializer = JSONWebTokenSerializer(data={})
        is_valid = serializer.is_valid()

        expected_error = {
            'username': ['This field is required.'],
            'password': ['This field is required.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)
