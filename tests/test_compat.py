import pytest
from django.test import TestCase
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from rest_framework.parsers import JSONParser
from rest_framework.exceptions import ParseError

from rest_framework_jwt.compat import get_request_data


class CompatTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def test_get_request_data(self):
        data = '{"a":"b"}'
        post = self.factory.post('/', data, content_type='application/json')
        request = Request(post, parsers=[JSONParser()])

        assert get_request_data(request) == {'a': 'b'}

    def test_get_request_data_invalid(self):
        data = '{a:b}'
        post = self.factory.post('/', data, content_type='application/json')
        request = Request(post, parsers=[JSONParser()])

        with pytest.raises(ParseError):
            get_request_data(request)
