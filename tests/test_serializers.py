import unittest
from distutils.version import StrictVersion

import django
from django.http import HttpRequest
from django.test import TestCase
from django.test.utils import override_settings

import rest_framework
from rest_framework.request import Request


from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.serializers import JSONWebTokenSerializer
from rest_framework_jwt import utils

User = get_user_model()

drf2 = rest_framework.VERSION < StrictVersion('3.0.0')
drf3 = rest_framework.VERSION >= StrictVersion('3.0.0')


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

    def get_serializer(self, **kwargs):
        serializer = JSONWebTokenSerializer(**kwargs)
        serializer.context['request'] = Request(HttpRequest()),
        return serializer

    @unittest.skipUnless(drf2, 'not supported in this version')
    def test_empty_drf2(self):
        serializer = self.get_serializer()
        expected = {
            'username': ''
        }

        self.assertEqual(serializer.data, expected)

    @unittest.skipUnless(drf3, 'not supported in this version')
    def test_empty_drf3(self):
        serializer = self.get_serializer()
        expected = {
            'username': '',
            'password': ''
        }

        self.assertEqual(serializer.data, expected)

    def test_create(self):
        serializer = self.get_serializer(data=self.data)
        is_valid = serializer.is_valid()

        token = serializer.object['token']
        decoded_payload = utils.jwt_decode_handler(token)

        self.assertTrue(is_valid)
        self.assertEqual(decoded_payload['username'], self.username)

    def test_invalid_credentials(self):
        self.data['password'] = 'wrong'
        serializer = self.get_serializer(data=self.data)
        is_valid = serializer.is_valid()

        expected_error = {
            'non_field_errors': ['Unable to log in with provided credentials.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)

    @unittest.skipIf(
        django.VERSION[1] >= 10,
        reason='The ModelBackend does not permit login when is_active is False.')
    def test_disabled_user(self):
        self.user.is_active = False
        self.user.save()

        serializer = self.get_serializer(data=self.data)
        is_valid = serializer.is_valid()

        expected_error = {
            'non_field_errors': ['User account is disabled.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)

    @unittest.skipUnless(
        django.VERSION[1] >= 10,
        reason='The AllowAllUsersModelBackend permits login when is_active is False.')
    @override_settings(AUTHENTICATION_BACKENDS=[
        'django.contrib.auth.backends.AllowAllUsersModelBackend'])
    def test_disabled_user_all_users_backend(self):
        self.user.is_active = False
        self.user.save()

        serializer = self.get_serializer(data=self.data)
        is_valid = serializer.is_valid()

        expected_error = {
            'non_field_errors': ['User account is disabled.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)

    def test_required_fields(self):
        serializer = self.get_serializer(data={})
        is_valid = serializer.is_valid()

        expected_error = {
            'username': ['This field is required.'],
            'password': ['This field is required.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)
