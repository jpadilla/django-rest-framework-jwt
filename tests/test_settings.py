# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from six.moves import reload_module

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from rest_framework_jwt import settings


def invalid_JWT_EXPIRATION_DELTA_setting():
    return {"JWT_EXPIRATION_DELTA": "invalid"}


def invalid_JWT_REFRESH_EXPIRATION_DELTA_setting():
    return {"JWT_REFRESH_EXPIRATION_DELTA": "invalid"}


class SettingsTestCase(TestCase):
    @classmethod
    def tearDownClass(cls):
        # prevent overridden settings from persisting across tests
        reload_module(settings)

    @override_settings(JWT_AUTH=invalid_JWT_EXPIRATION_DELTA_setting())
    def test_invalid_JWT_EXPIRATION_DELTA_setting(self):
        with self.assertRaises(ImproperlyConfigured):
            reload_module(settings)

    @override_settings(JWT_AUTH=invalid_JWT_REFRESH_EXPIRATION_DELTA_setting())
    def test_invalid_JWT_REFRESH_EXPIRATION_DELTA_setting(self):
        with self.assertRaises(ImproperlyConfigured):
            reload_module(settings)
